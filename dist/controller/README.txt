Controller UI - House A (Go-native WPF clone)
=============================================
Run:
  controller-ui.exe -addr 0.0.0.0:4444 -cert server.crt -key server.key -http 127.0.0.1:8080 -open
Then open http://127.0.0.1:8080/ in browser (auto-opens with -open)

Features:
 - Connections sidebar (filter, add, discover, refresh, quick connect)
 - Device switcher + latency badge
 - Screen tab: Start/Stop, Monitor selector, Mirror/Dual toggles, FPS selector, scroll, console, audio
 - Files tab: Local/Remote dual pane, path bars, filters, copy →/←, progress, delete, favorites
 - Commands tab: Favorites, search, terminal (Consolas), autocomplete (Tab), history (↑↓), 100+ commands (help)
 - Audio tab: Desktop/Mic/Both, device selector, mute, volume
 - TLS 1.2+ encrypted (server.crt SAN 127.0.0.1 + 176.229.98.54)
 - WebSocket live: screen, mouse, output, file lists

Headless:
  controller.exe -addr :4444 -cert server.crt -key server.key -http 127.0.0.1:8080

Firewall: netsh advfirewall firewall add rule name="RMM 4444" dir=in action=allow protocol=TCP localport=4444
Port forward: router 4444 -> this PC (check public IP 176.229.98.54)
