//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	modKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procSetThreadExecState = modKernel32.NewProc("SetThreadExecutionState")
)

const (
	esContinuous       = 0x80000000
	esSystemRequired   = 0x00000001
	esDisplayRequired  = 0x00000002
	keepAwakePrefFile  = "keepawake.txt"
)

// keepAwakePrefFilePath persists the on/off choice across restarts.
func keepAwakePrefPath() string {
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		return filepath.Join(localApp, "RMM", keepAwakePrefFile)
	}
	return filepath.Join(os.TempDir(), "RMM", keepAwakePrefFile)
}

// applyKeepAwake tells Windows this PC must not sleep/lock while the agent
// runs. Per-thread + process-lifetime: must run in the agent process
// itself (a one-shot powershell call would evaporate on exit).
func applyKeepAwake(on bool) {
	var flags uintptr
	if on {
		flags = esContinuous | esSystemRequired | esDisplayRequired
	} else {
		flags = esContinuous
	}
	procSetThreadExecState.Call(flags)
}

// readKeepAwakePref defaults ON (always-on unless opted out).
func readKeepAwakePref() bool {
	dir := filepath.Dir(keepAwakePrefPath())
	_ = os.MkdirAll(dir, 0755)
	b, err := os.ReadFile(keepAwakePrefPath())
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(b)) != "off"
}

// EnsureKeepAwake reads the persisted pref (default ON) and applies it.
// Called once at agent startup; the command path re-applies on change.
func EnsureKeepAwake() {
	applyKeepAwake(readKeepAwakePref())
}

// keepAwake implements: keep-awake [on|off|status].
func keepAwake(arg string) (string, error) {
	switch a := strings.ToLower(strings.TrimSpace(arg)); a {
	case "", "status":
		if readKeepAwakePref() {
			return "keep-awake: on (display + sleep blocked while agent runs)", nil
		}
		return "keep-awake: off", nil
	case "on", "1", "true":
		dir := filepath.Dir(keepAwakePrefPath())
		_ = os.MkdirAll(dir, 0755)
		if err := os.WriteFile(keepAwakePrefPath(), []byte("on"), 0644); err != nil {
			return "", err
		}
		applyKeepAwake(true)
		return "keep-awake: on", nil
	case "off", "0", "false":
		dir := filepath.Dir(keepAwakePrefPath())
		_ = os.MkdirAll(dir, 0755)
		if err := os.WriteFile(keepAwakePrefPath(), []byte("off"), 0644); err != nil {
			return "", err
		}
		applyKeepAwake(false)
		return "keep-awake: off", nil
	default:
		return "", fmt.Errorf("usage: keep-awake [on|off|status]")
	}
}
