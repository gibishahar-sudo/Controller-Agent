RMM Controller Setup - Developer App
======================================
Run Controller-Setup.exe (requires Admin)
- Installs to: C:\Program Files\RMM\Controller\
  - controller-ui.exe (Go-native UI, auto-opens browser)
  - controller.exe (headless)
  - server.crt / server.key (TLS, SAN 176.229.98.54)
- Creates: Desktop\ code
  "Controller.lnk" -> C:\Program Files\RMM\Controller\controller-ui.exe
  Start Menu\RMM Controller.lnk
- Firewall: adds inbound TCP 4444 allow
- Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RMM Controller
- Uninstall: C:\Program Files\RMM\Controller\uninstall.exe or Add/Remove Programs
Usage after install:
  Double-click Desktop\Controller.lnk  (or run controller-ui.exe -open)
  UI at http://127.0.0.1:8080/  (TLS agents on 0.0.0.0:4444)
