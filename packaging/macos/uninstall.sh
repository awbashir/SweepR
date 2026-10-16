#!/bin/bash
# SweepR uninstaller for macOS ("Uninstall SweepR.command" on the disk image).
#
# Removes the apps, the sweepr PATH entries (/usr/local/bin/sweepr, /etc/paths.d/sweepr) and
# SweepR's packet-capture boot job.
# Your settings and hostname overrides (~/Library/Application Support/com.SweepR.SweepR) and
# the access_bpf group (Wireshark uses it too) are kept; to drop the group as well:
#   sudo dseditgroup -o delete access_bpf
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "SweepR uninstaller: administrator rights are needed; enter your password if asked."
  exec sudo /bin/bash "${BASH_SOURCE[0]}" "$@"
fi

bin_link=/usr/local/bin/sweepr
if [ -L "$bin_link" ] && [[ "$(readlink "$bin_link")" == */SweepR.app/* ]]; then
  echo "==> Removing $bin_link"
  rm -f "$bin_link"
fi
if [ -f /etc/paths.d/sweepr ]; then
  echo "==> Removing /etc/paths.d/sweepr"
  rm -f /etc/paths.d/sweepr
fi

if [ -f /Library/LaunchDaemons/com.sweepr.chmodbpf.plist ]; then
  echo "==> Removing the packet-capture boot job"
  launchctl bootout system/com.sweepr.chmodbpf 2>/dev/null || true
  rm -f /Library/LaunchDaemons/com.sweepr.chmodbpf.plist
fi
rm -rf "/Library/Application Support/SweepR"

for app in "/Applications/SweepR (Administrator).app" /Applications/SweepR.app; do
  if [ -d "$app" ]; then
    echo "==> Removing $app"
    rm -rf "$app"
  fi
done

echo "SweepR has been removed."
