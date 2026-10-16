//! Saving GUI-rendered files (the topology map as SVG or PNG) through the backend's native save
//! dialog (`save_file` command). The webview supplies only the content, a suggested file name
//! and the kind; the path always comes from the dialog. The content is checked against its kind
//! (a PNG signature, an SVG document) and bounded, and the write never follows a symbolic link
//! or replaces a non-regular file (the same hardened open as reports).

use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{bail, Context, Result};
use base64::Engine as _;

/// Largest file `save_file` writes (decoded bytes).
pub const SAVE_FILE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Longest suggested file name kept (characters, extension included).
const MAX_NAME_CHARS: usize = 120;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// What `save_file` writes. The kind fixes the extension, the dialog filter and how the
/// content is passed: SVG as UTF-8 text, PNG as standard base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveKind {
    Svg,
    Png,
}

impl SaveKind {
    pub fn ext(self) -> &'static str {
        match self {
            Self::Svg => "svg",
            Self::Png => "png",
        }
    }

    /// Save-dialog filter label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Svg => "SVG image",
            Self::Png => "PNG image",
        }
    }

    /// The kind a path's extension names (case-insensitive), if any.
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()?.to_str()?.parse().ok()
    }
}

impl fmt::Display for SaveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.ext())
    }
}

impl FromStr for SaveKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "svg" => Ok(Self::Svg),
            "png" => Ok(Self::Png),
            other => bail!("unsupported file kind '{other}' (expected svg or png)"),
        }
    }
}

/// Decode and check `contents` for `kind`: SVG is the text itself and must be an SVG document;
/// PNG is base64 (a `data:image/png;base64,` prefix is accepted) and must carry the PNG
/// signature. Anything over [`SAVE_FILE_MAX_BYTES`] is refused before decoding.
pub fn decode_contents(kind: SaveKind, contents: &str) -> Result<Vec<u8>> {
    match kind {
        SaveKind::Svg => {
            if contents.len() > SAVE_FILE_MAX_BYTES {
                bail!(
                    "the SVG is too large to save ({} MiB max)",
                    SAVE_FILE_MAX_BYTES >> 20
                );
            }
            if !looks_like_svg(contents) {
                bail!("the content is not an SVG document");
            }
            Ok(contents.as_bytes().to_vec())
        }
        SaveKind::Png => {
            let b64 = contents
                .strip_prefix("data:image/png;base64,")
                .unwrap_or(contents)
                .trim();
            // 4 base64 characters carry 3 bytes.
            if b64.len() / 4 * 3 > SAVE_FILE_MAX_BYTES + 3 {
                bail!(
                    "the PNG is too large to save ({} MiB max)",
                    SAVE_FILE_MAX_BYTES >> 20
                );
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .context("the PNG data is not valid base64")?;
            if bytes.len() > SAVE_FILE_MAX_BYTES {
                bail!(
                    "the PNG is too large to save ({} MiB max)",
                    SAVE_FILE_MAX_BYTES >> 20
                );
            }
            if !bytes.starts_with(PNG_SIGNATURE) {
                bail!("the content is not a PNG image");
            }
            Ok(bytes)
        }
    }
}

/// An SVG document: optional BOM, whitespace, XML declaration, comments or doctype, then `<svg`.
fn looks_like_svg(text: &str) -> bool {
    let mut rest = text.trim_start_matches('\u{feff}').trim_start();
    loop {
        if rest.starts_with("<svg") {
            return true;
        }
        let close = if rest.starts_with("<?") {
            "?>"
        } else if rest.starts_with("<!--") {
            "-->"
        } else if rest.starts_with("<!") {
            ">"
        } else {
            return false;
        };
        match rest.find(close) {
            Some(i) => rest = rest[i + close.len()..].trim_start(),
            None => return false,
        }
    }
}

/// The file name the dialog proposes: the last component of `suggested` with control and
/// path-separator characters removed, bounded in length, ending in the kind's extension.
pub fn suggested_file_name(suggested: Option<&str>, kind: SaveKind) -> String {
    let fallback = format!("sweepr-topology.{kind}");
    let Some(raw) = suggested else {
        return fallback;
    };
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, ':' | '/' | '\\'))
        .collect();
    let cleaned = cleaned.trim();
    let ext = format!(".{kind}");
    let stem = if cleaned.to_ascii_lowercase().ends_with(&ext) {
        &cleaned[..cleaned.len() - ext.len()]
    } else {
        cleaned
    };
    // No hidden files.
    let stem = stem.trim_start_matches('.').trim();
    let stem: String = stem.chars().take(MAX_NAME_CHARS - ext.len()).collect();
    let stem = stem.trim();
    if stem.is_empty() {
        return fallback;
    }
    format!("{stem}{ext}")
}

/// Final path for a dialog choice: a missing extension is added (refusing to replace an
/// existing file the dialog never asked about); any other extension must match `kind`.
pub fn resolve_chosen_path(
    chosen: PathBuf,
    kind: SaveKind,
) -> std::result::Result<PathBuf, String> {
    if chosen.extension().is_some() {
        return match SaveKind::from_path(&chosen) {
            Some(k) if k == kind => Ok(chosen),
            _ => Err(format!(
                "the file name must end in .{kind} for a {kind} image"
            )),
        };
    }
    let mut path = chosen.into_os_string();
    path.push(format!(".{kind}"));
    let path = PathBuf::from(path);
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(format!(
            "{} already exists; choose it explicitly to replace it",
            path.display()
        ));
    }
    Ok(path)
}

/// Write `bytes` to a path chosen interactively: the extension must match `kind`; symbolic
/// links and non-regular files are refused.
pub fn write_to_chosen_path(bytes: &[u8], kind: SaveKind, path: &Path) -> Result<()> {
    if SaveKind::from_path(path) != Some(kind) {
        bail!(
            "file name {} does not end in .{kind}",
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        );
    }
    if bytes.len() > SAVE_FILE_MAX_BYTES {
        bail!(
            "the file is too large to save ({} MiB max)",
            SAVE_FILE_MAX_BYTES >> 20
        );
    }
    crate::report::write_file_no_follow(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVG: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- SweepR -->
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"></svg>"#;

    fn png_b64() -> String {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(b"rest of the image");
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sweepr-save-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn kinds_parse_and_match_paths() {
        assert_eq!("PNG".parse::<SaveKind>().unwrap(), SaveKind::Png);
        assert_eq!(" svg ".parse::<SaveKind>().unwrap(), SaveKind::Svg);
        assert!("exe".parse::<SaveKind>().is_err());
        assert_eq!(
            SaveKind::from_path(Path::new("/a/map.PNG")),
            Some(SaveKind::Png)
        );
        assert_eq!(SaveKind::from_path(Path::new("/a/map")), None);
    }

    #[test]
    fn contents_are_checked_against_the_kind() {
        assert_eq!(decode_contents(SaveKind::Svg, SVG).unwrap(), SVG.as_bytes());
        assert!(decode_contents(SaveKind::Svg, "\u{feff}  <svg/>").is_ok());
        assert!(decode_contents(SaveKind::Svg, "<html><svg/></html>").is_err());
        assert!(decode_contents(SaveKind::Svg, "#!/bin/sh\nrm -rf ~").is_err());
        assert!(decode_contents(SaveKind::Svg, "<!-- unterminated").is_err());

        let png = decode_contents(SaveKind::Png, &png_b64()).unwrap();
        assert!(png.starts_with(PNG_SIGNATURE));
        let data_url = format!("data:image/png;base64,{}", png_b64());
        assert_eq!(decode_contents(SaveKind::Png, &data_url).unwrap(), png);
        assert!(decode_contents(SaveKind::Png, "not base64!").is_err());
        let not_png = base64::engine::general_purpose::STANDARD.encode(b"GIF89a....");
        assert!(decode_contents(SaveKind::Png, &not_png).is_err());
    }

    #[test]
    fn oversized_contents_are_refused_before_decoding() {
        let huge = "A".repeat((SAVE_FILE_MAX_BYTES / 3 + 8) * 4);
        let err = decode_contents(SaveKind::Png, &huge)
            .unwrap_err()
            .to_string();
        assert!(err.contains("too large"), "{err}");
        let mut svg = String::from("<svg>");
        svg.push_str(&" ".repeat(SAVE_FILE_MAX_BYTES));
        assert!(decode_contents(SaveKind::Svg, &svg).is_err());
    }

    #[test]
    fn suggested_names_are_sanitized() {
        let png = SaveKind::Png;
        assert_eq!(suggested_file_name(None, png), "sweepr-topology.png");
        assert_eq!(suggested_file_name(Some("map.png"), png), "map.png");
        assert_eq!(suggested_file_name(Some("map.PNG"), png), "map.png");
        assert_eq!(suggested_file_name(Some("map"), png), "map.png");
        assert_eq!(suggested_file_name(Some("map.svg"), png), "map.svg.png");
        assert_eq!(
            suggested_file_name(Some("../../etc/passwd"), png),
            "passwd.png"
        );
        assert_eq!(
            suggested_file_name(Some("C:\\x\\evil.png"), png),
            "evil.png"
        );
        assert_eq!(suggested_file_name(Some("a\u{0}b\nc.png"), png), "abc.png");
        assert_eq!(suggested_file_name(Some(".hidden"), png), "hidden.png");
        assert_eq!(suggested_file_name(Some("  "), png), "sweepr-topology.png");
        assert_eq!(
            suggested_file_name(Some(".png"), png),
            "sweepr-topology.png"
        );
        let long = suggested_file_name(Some(&"x".repeat(500)), SaveKind::Svg);
        assert_eq!(long.chars().count(), MAX_NAME_CHARS);
        assert!(long.ends_with(".svg"));
    }

    #[test]
    fn chosen_paths_enforce_the_extension_and_never_replace_silently() {
        let dir = tmp_dir("resolve");
        assert_eq!(
            resolve_chosen_path(dir.join("map.png"), SaveKind::Png).unwrap(),
            dir.join("map.png")
        );
        assert!(resolve_chosen_path(dir.join("map.txt"), SaveKind::Png).is_err());
        assert!(resolve_chosen_path(dir.join("map.svg"), SaveKind::Png).is_err());
        assert_eq!(
            resolve_chosen_path(dir.join("map"), SaveKind::Svg).unwrap(),
            dir.join("map.svg")
        );
        std::fs::write(dir.join("taken.svg"), "old").unwrap();
        let err = resolve_chosen_path(dir.join("taken"), SaveKind::Svg).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_refuse_wrong_extensions_and_symlinks() {
        let dir = tmp_dir("write");
        let ok = dir.join("map.svg");
        write_to_chosen_path(SVG.as_bytes(), SaveKind::Svg, &ok).unwrap();
        assert_eq!(std::fs::read_to_string(&ok).unwrap(), SVG);
        // An explicitly chosen existing file is replaced (the dialog confirmed it).
        write_to_chosen_path(b"<svg/>", SaveKind::Svg, &ok).unwrap();
        assert_eq!(std::fs::read_to_string(&ok).unwrap(), "<svg/>");
        assert!(write_to_chosen_path(b"<svg/>", SaveKind::Png, &ok).is_err());
        assert!(write_to_chosen_path(b"<svg/>", SaveKind::Svg, &dir.join("map.txt")).is_err());
        #[cfg(unix)]
        {
            let target = dir.join("target.txt");
            std::fs::write(&target, "keep").unwrap();
            let link = dir.join("link.svg");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let err = write_to_chosen_path(b"<svg/>", SaveKind::Svg, &link).unwrap_err();
            assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        }
        std::fs::create_dir_all(dir.join("dir.svg")).unwrap();
        assert!(write_to_chosen_path(b"<svg/>", SaveKind::Svg, &dir.join("dir.svg")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
