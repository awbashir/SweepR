SweepR for macOS
================

Install (recommended)
  Double-click "Install SweepR.command" and enter your administrator password.
  It copies SweepR and "SweepR (Administrator)" to /Applications, links the
  command-line tool to /usr/local/bin/sweepr and can optionally let your user
  capture packets without sudo.

  If macOS refuses to open the installer ("cannot be verified"), either
  right-click it > Open, allow it under System Settings > Privacy & Security,
  or run it from Terminal:
      bash "/Volumes/SweepR <version>/Install SweepR.command"

Drag-and-drop install
  Drag SweepR.app (and optionally "SweepR (Administrator).app") onto the
  Applications folder. If macOS then says the app is damaged or cannot be
  verified, clear the download flag:
      xattr -dr com.apple.quarantine /Applications/SweepR.app

Which app to open
  SweepR (Administrator)  Full scans: ARP, 802.1Q VLAN probes, IPv6 neighbor
                          discovery, CDP/LLDP listening. Asks for your
                          administrator password each time.
  SweepR                  Runs without root: ICMP sweep and the neighbor cache
                          only, so hosts that block ping can be missed.
  Terminal                sudo sweepr scan    (sweepr --help for all commands)

Files SweepR writes while running as root (exports, reports, hostname
overrides) are handed back to your user.

Uninstall
  Double-click "Uninstall SweepR.command".
