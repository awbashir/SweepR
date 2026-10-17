#!/usr/bin/env bash
# Package a built `sweepr` binary for download:
#
#   scripts/package-binary.sh <version> <platform> <binary> [out-dir]
#
#   <platform>  macos-arm64 | macos-universal | linux-x86_64 | linux-aarch64 | windows-x86_64
#   <out-dir>   default: dist-bin
#
# Writes <out-dir>/sweepr-<version>-<platform>.tar.gz (.zip for Windows) holding the binary,
# LICENSE (when the repository has one) and INSTALL.txt, plus a matching .sha256 file.
# Used by .github/workflows/build-binaries.yml; works the same locally.
set -euo pipefail

if [ $# -lt 3 ]; then
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
fi
version=$1 platform=$2 binary=$3 out=${4:-dist-bin}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
name="sweepr-${version}-${platform}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
dir="$stage/$name"
mkdir -p "$dir"

case "$platform" in
  windows-*) exe=sweepr.exe ;;
  macos-* | linux-*) exe=sweepr ;;
  *) echo "unknown platform: $platform" >&2; exit 2 ;;
esac
cp "$binary" "$dir/$exe"
chmod 755 "$dir/$exe"
for f in LICENSE LICENSE.md LICENSE.txt COPYING; do
  if [ -f "$root/$f" ]; then cp "$root/$f" "$dir/"; fi
done

repo="https://github.com/awbashir/SweepR"
case "$platform" in
  macos-*)
    if [ "$platform" = macos-universal ]; then arch="Apple Silicon and Intel (universal)"; else arch="Apple Silicon (arm64)"; fi
    cat > "$dir/INSTALL.txt" <<EOF
SweepR $version for macOS, $arch

Install (puts sweepr on your PATH):
  xattr -d com.apple.quarantine sweepr 2> /dev/null   # if macOS blocks it: ad-hoc signed, not notarized
  sudo install -m 755 sweepr /usr/local/bin/sweepr
or without sudo:
  mkdir -p ~/.local/bin && install -m 755 sweepr ~/.local/bin/sweepr   # ~/.local/bin must be on PATH

Run:
  sweepr              desktop app (GUI); same as sweepr --gui
  sudo sweepr --gui   GUI with raw ARP / 802.1Q / IPv6 NDP / CDP-LLDP capture
  sudo sweepr scan    command line scan of the default interface's subnet
  sweepr --help       all commands

Without root SweepR falls back to an ICMP sweep plus the neighbor cache.
Documentation: $repo
EOF
    ;;
  linux-*)
    cat > "$dir/INSTALL.txt" <<EOF
SweepR $version for Linux (${platform#linux-})

Runtime libraries:
  Debian / Ubuntu: sudo apt install libwebkit2gtk-4.1-0 libgtk-3-0 libpcap0.8
  Fedora:          sudo dnf install webkit2gtk4.1 gtk3 libpcap

Install (puts sweepr on your PATH):
  sudo install -m 755 sweepr /usr/local/bin/sweepr
or without sudo:
  mkdir -p ~/.local/bin && install -m 755 sweepr ~/.local/bin/sweepr   # ~/.local/bin must be on PATH

Raw ARP / 802.1Q / IPv6 NDP / CDP-LLDP capture needs root or these capabilities (once):
  sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/sweepr

Run:
  sweepr              desktop app (GUI)
  sweepr scan         command line scan of the default interface's subnet
  sweepr --help       all commands

Documentation: $repo
EOF
    ;;
  windows-*)
    cat > "$dir/INSTALL.txt" <<EOF
SweepR $version for Windows (x86_64)

1. Install Npcap from https://npcap.com (raw ARP / 802.1Q / IPv6 NDP / CDP-LLDP / DHCP
   capture). Without it SweepR still runs and falls back to an ICMP sweep.
2. Put sweepr.exe on your PATH (PowerShell, no administrator rights needed):

     \$dir = "\$env:LOCALAPPDATA\\Programs\\SweepR"
     New-Item -ItemType Directory -Force \$dir | Out-Null
     Copy-Item .\\sweepr.exe \$dir
     \$path = [Environment]::GetEnvironmentVariable("Path", "User")
     [Environment]::SetEnvironmentVariable("Path", "\$path;\$dir", "User")

   Then open a new terminal.
3. Run:
     sweepr              desktop app (GUI; needs the WebView2 runtime, built into Windows 10/11)
     sweepr scan         command line scan of the default interface's subnet
     sweepr interfaces   adapters by connection name (use them with -i "Ethernet")
     sweepr --help       all commands

If Npcap was installed with "Restrict Npcap driver's access to Administrators only", run
SweepR from an elevated terminal (Run as administrator).
Documentation: $repo
EOF
    ;;
esac

case "$platform" in
  windows-*)
    archive="$name.zip"
    rm -f "$out/$archive"
    if command -v 7z > /dev/null 2>&1; then
      (cd "$stage" && 7z a -tzip -bd "$out/$archive" "$name" > /dev/null)
    elif command -v zip > /dev/null 2>&1; then
      (cd "$stage" && zip -qr "$out/$archive" "$name")
    else
      (cd "$stage" && powershell -NoProfile -Command \
        "Compress-Archive -Path '$name' -DestinationPath '$(cygpath -w "$out/$archive")'")
    fi
    ;;
  *)
    archive="$name.tar.gz"
    # No macOS extended attributes / AppleDouble files in the archive.
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -czf "$out/$archive" "$name"
    ;;
esac

if command -v sha256sum > /dev/null 2>&1; then
  (cd "$out" && sha256sum "$archive" > "$archive.sha256")
else
  (cd "$out" && shasum -a 256 "$archive" > "$archive.sha256")
fi
echo "$out/$archive"
