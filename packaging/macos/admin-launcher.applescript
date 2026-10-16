-- SweepR (Administrator): starts SweepR as root so it can send raw ARP, 802.1Q and IPv6
-- neighbor-discovery probes. macOS asks for an administrator password each time.
--
-- HOME stays the user's, so settings and hostname overrides are shared with normal launches;
-- SUDO_UID / SUDO_GID tell SweepR to hand files it creates (exports, reports, the overrides
-- store) back to the user instead of leaving them owned by root.

on run
	set homeDir to do shell script "printf %s \"$HOME\""
	set myFolder to do shell script "dirname " & quoted form of (POSIX path of (path to me))
	set candidates to {"/Applications/SweepR.app", homeDir & "/Applications/SweepR.app", myFolder & "/SweepR.app"}

	set binPath to ""
	repeat with appPath in candidates
		try
			set exeName to do shell script "/usr/bin/plutil -extract CFBundleExecutable raw " & quoted form of (appPath & "/Contents/Info.plist")
			set candidateBin to appPath & "/Contents/MacOS/" & exeName
			do shell script "test -x " & quoted form of candidateBin
			set binPath to candidateBin
			exit repeat
		end try
	end repeat

	if binPath is "" then
		display alert "SweepR is not installed" message "Run “Install SweepR” from the SweepR disk image (or move SweepR.app to the Applications folder), then open this launcher again." as critical
		return
	end if

	set uid to do shell script "id -u"
	set gid to do shell script "id -g"
	set userName to do shell script "id -un"
	set cmd to "export HOME=" & quoted form of homeDir & " SUDO_UID=" & uid & " SUDO_GID=" & gid & " SUDO_USER=" & quoted form of userName & "; " & quoted form of binPath & " --gui >/dev/null 2>&1 &"

	try
		do shell script cmd with prompt "SweepR needs administrator rights to send raw ARP, 802.1Q VLAN and IPv6 probes." with administrator privileges
	on error errMsg number errNum
		-- -128: the user cancelled the password prompt.
		if errNum is not -128 then display alert "SweepR could not start" message errMsg as critical
	end try
end run
