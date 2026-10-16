#!/bin/bash
# Build the SweepR installer disk image for macOS.
#
#   packaging/macos/build-dmg.sh                                   # this Mac's architecture
#   SWEEPR_TARGET=universal-apple-darwin packaging/macos/build-dmg.sh  # Apple Silicon + Intel
#
# The image holds SweepR.app, "SweepR (Administrator).app" (starts SweepR as root after an
# administrator password prompt), "Install SweepR.command" (sudo installer: apps, CLI link,
# optional packet-capture access), "Uninstall SweepR.command", a Read Me and an Applications
# link. Output: src-tauri/target/dmg/SweepR_<version>_<arch>.dmg
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
target="${SWEEPR_TARGET:-}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: the disk image can only be built on macOS (needs hdiutil and osacompile)" >&2
  exit 1
fi

cd "$root"
[ -d node_modules ] || npm ci

build_args=(--bundles app)
if [ -n "$target" ]; then
  if [ "$target" = "universal-apple-darwin" ] && command -v rustup >/dev/null 2>&1; then
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
  fi
  build_args+=(--target "$target")
  bundle_dir="src-tauri/target/$target/release/bundle/macos"
else
  bundle_dir="src-tauri/target/release/bundle/macos"
fi
npx tauri build "${build_args[@]}"

app="$bundle_dir/SweepR.app"
[ -d "$app" ] || { echo "error: $app was not built" >&2; exit 1; }
version="$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")"
# The Read Me and README tell drag-and-drop users to link Contents/MacOS/sweepr.
exe="$(plutil -extract CFBundleExecutable raw "$app/Contents/Info.plist")"
if [ "$exe" != sweepr ]; then
  echo "error: the bundle executable is '$exe', expected 'sweepr' (update the docs)" >&2
  exit 1
fi
case "$target" in
  universal-apple-darwin) arch=universal ;;
  aarch64-apple-darwin) arch=aarch64 ;;
  x86_64-apple-darwin) arch=x64 ;;
  *) arch="$(uname -m | sed 's/arm64/aarch64/; s/x86_64/x64/')" ;;
esac

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

ditto "$app" "$stage/SweepR.app"

launcher="$stage/SweepR (Administrator).app"
osacompile -o "$launcher" "$here/admin-launcher.applescript"
cp src-tauri/icons/icon.icns "$launcher/Contents/Resources/applet.icns"
# Changing the icon invalidates osacompile's signature: sign it again (ad hoc).
codesign --force --deep --sign - "$launcher"

install -m 755 "$here/install.sh" "$stage/Install SweepR.command"
install -m 755 "$here/uninstall.sh" "$stage/Uninstall SweepR.command"
install -m 644 "$here/ReadMe.txt" "$stage/Read Me.txt"
ln -s /Applications "$stage/Applications"

out_dir="src-tauri/target/dmg"
mkdir -p "$out_dir"
dmg="$out_dir/SweepR_${version}_${arch}.dmg"
rm -f "$dmg"
hdiutil create -volname "SweepR $version" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg"
echo "built $dmg"
