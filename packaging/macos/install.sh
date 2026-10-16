#!/bin/bash
# SweepR installer for macOS ("Install SweepR.command" on the disk image).
#
# Double-click it in the opened disk image, or run it from Terminal:
#   bash "/Volumes/SweepR <version>/Install SweepR.command" [--bpf | --no-bpf]
#
# It asks for your administrator password (sudo) and then:
#   1. copies SweepR.app and "SweepR (Administrator).app" to /Applications
#   2. removes the download quarantine flag from them (the app is not notarized)
#   3. links the command-line tool to /usr/local/bin/sweepr (`sudo sweepr scan ...`)
#   4. optionally (asked, or --bpf / --no-bpf) gives your user read/write access to the
#      packet-capture devices (/dev/bpf*) at every boot, so passive VLAN / CDP / LLDP
#      listening works without sudo. Active ARP / 802.1Q / NDP scans still need root: use
#      "SweepR (Administrator)" or `sudo sweepr`.
set -euo pipefail

src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bpf_choice=ask
for arg in "$@"; do
  case "$arg" in
    --bpf) bpf_choice=yes ;;
    --no-bpf) bpf_choice=no ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "SweepR installer: administrator rights are needed; enter your password if asked."
  exec sudo /bin/bash "${BASH_SOURCE[0]}" "$@"
fi
user="${SUDO_USER:-}"

apps=/Applications
app="$apps/SweepR.app"
launcher="$apps/SweepR (Administrator).app"
bin_link=/usr/local/bin/sweepr
support="/Library/Application Support/SweepR"
daemon=/Library/LaunchDaemons/com.sweepr.chmodbpf.plist
bpf_group=access_bpf

[ -d "$src/SweepR.app" ] || { echo "error: SweepR.app not found next to this installer" >&2; exit 1; }

if pgrep -xq sweepr; then
  echo "note: SweepR is running; quit it first if the copy below fails."
fi

echo "==> Installing $app"
rm -rf "$app"
ditto "$src/SweepR.app" "$app"
if [ -d "$src/SweepR (Administrator).app" ]; then
  echo "==> Installing $launcher"
  rm -rf "$launcher"
  ditto "$src/SweepR (Administrator).app" "$launcher"
fi
for a in "$app" "$launcher"; do
  if [ -d "$a" ]; then xattr -dr com.apple.quarantine "$a" 2>/dev/null || true; fi
done

exe="$(plutil -extract CFBundleExecutable raw "$app/Contents/Info.plist")"
echo "==> Linking $bin_link -> $app/Contents/MacOS/$exe"
mkdir -p /usr/local/bin
if [ -e "$bin_link" ] && [ ! -L "$bin_link" ]; then
  echo "    skipped: $bin_link exists and is not a link (remove it to use the bundled CLI)"
else
  ln -sfn "$app/Contents/MacOS/$exe" "$bin_link"
fi

if [ "$bpf_choice" = ask ]; then
  echo
  echo "Optional: let ${user:-your user} capture packets without sudo (passive VLAN, CDP/LLDP"
  echo "and DHCP listening). This adds the user to the '$bpf_group' group and installs a small"
  echo "boot-time job that makes /dev/bpf* readable/writable by that group (like Wireshark's"
  echo "ChmodBPF). Active ARP / 802.1Q / IPv6 scans still need 'SweepR (Administrator)'."
  read -r -p "Grant packet-capture access? [y/N] " reply </dev/tty || reply=
  case "$reply" in [yY]*) bpf_choice=yes ;; *) bpf_choice=no ;; esac
fi

if [ "$bpf_choice" = yes ]; then
  if [ -z "$user" ] || [ "$user" = root ]; then
    echo "    skipped packet-capture access: cannot tell which user to grant it to"
  else
    echo "==> Granting $user packet-capture access ($bpf_group)"
    if ! dscl . -read "/Groups/$bpf_group" >/dev/null 2>&1; then
      dseditgroup -o create -r "Packet capture (BPF) access" "$bpf_group"
    fi
    dseditgroup -o edit -a "$user" -t user "$bpf_group" ||
      echo "    warning: could not add $user to $bpf_group"

    if [ -f /Library/LaunchDaemons/org.wireshark.ChmodBPF.plist ]; then
      echo "    Wireshark's ChmodBPF is installed and already manages /dev/bpf*; using it."
    else
      install -d -m 755 -o root -g wheel "$support"
      cat > "$support/chmodbpf.sh" <<'EOF'
#!/bin/bash
# Installed by SweepR: give the access_bpf group read/write access to the BPF devices.
# macOS creates /dev/bpf* on demand, so touch them first (up to debug.bpf_maxdevices).
max=256
sysmax="$(sysctl -n debug.bpf_maxdevices 2>/dev/null || echo "$max")"
[ "$sysmax" -lt "$max" ] && max="$sysmax"
i=0
while [ "$i" -lt "$max" ]; do
  read -r -n 0 < "/dev/bpf$i" > /dev/null 2>&1
  i=$((i + 1))
done
chgrp access_bpf /dev/bpf*
chmod g+rw /dev/bpf*
EOF
      chown root:wheel "$support/chmodbpf.sh"
      chmod 755 "$support/chmodbpf.sh"
      cat > "$daemon" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.sweepr.chmodbpf</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$support/chmodbpf.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
EOF
      chown root:wheel "$daemon"
      chmod 644 "$daemon"
      launchctl bootout system/com.sweepr.chmodbpf 2>/dev/null || true
      launchctl bootstrap system "$daemon"
    fi
    echo "    Log out and back in (or restart) for the group membership to take effect."
  fi
fi

cat <<EOF

SweepR is installed.
  * SweepR (Administrator)  full scans (ARP, 802.1Q VLANs, IPv6, CDP/LLDP); asks for your password
  * SweepR                  runs without root (ICMP sweep + neighbor cache)
  * Terminal                sudo sweepr scan   |   sweepr --help
EOF
