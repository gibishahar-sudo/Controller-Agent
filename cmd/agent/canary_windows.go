//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// canaryStateDir locates canaryname.txt (install dir preferred, Temp/RMM
// fallback — mirrors the lock-dir policy).
func canaryStateDir(installDir string) string {
	if installDir != "" {
		return installDir
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		return filepath.Join(la, "RMM")
	}
	return filepath.Join(os.TempDir(), "RMM")
}

var canaryRunPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// readRunValue reads one Run value (ok=false when missing/unreadable).
func readRunValue(root registry.Key, name string) (string, bool) {
	k, err := registry.OpenKey(root, canaryRunPath, registry.READ)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return "", false
	}
	return v, true
}

// plantCanaries ensures both canary values exist (inert target). Silent.
func plantCanaries(root registry.Key, stateDir string) {
	random, _ := canaryRandomName(stateDir)
	if random == "" {
		return
	}
	k, _, err := registry.CreateKey(root, canaryRunPath, registry.WRITE)
	if err != nil {
		return
	}
	defer k.Close()
	if _, ok := readRunValue(root, canaryPatternName); !ok {
		_ = k.SetStringValue(canaryPatternName, canaryInertCmd)
	}
	if _, ok := readRunValue(root, random); !ok {
		_ = k.SetStringValue(random, canaryInertCmd)
	}
}

// auditRunCanaries checks the two real values + both canaries, replants
// missing canaries, and returns a verdict word for the alarm path.
// "clean" and "unplanted" never alarm.
func auditRunCanaries(root registry.Key, stateDir string) string {
	_, oursA := readRunValue(root, "WindowsUpdate")
	_, oursB := readRunValue(root, "WindowsUpdateWatchdog")
	_, pattern := readRunValue(root, canaryPatternName)
	random, isNew := canaryRandomName(stateDir)
	if random == "" {
		return "clean"
	}
	if isNew {
		// First sight: bait the trap, never verdict.
		plantCanaries(root, stateDir)
		return "unplanted"
	}
	_, randPresent := readRunValue(root, random)
	plantCanaries(root, stateDir)
	switch canaryVerdict(oursA, oursB, pattern, randPresent) {
	case "targeted":
		return "targeted: ours + pattern canary deleted, random survivor — actor knows our naming"
	case "bulk":
		return "bulk: all Run values incl. canaries wiped — profile cleaner/GPO/script"
	case "surgical":
		return "surgical: only our values removed, canaries untouched"
	default:
		return "clean"
	}
}

// checkRunCanaries is the watch-loop hook: audit HKLM Run, alarm the
// tripwire on hostile verdicts (sticky, like all tamper alarms — a
// reinstall re-baits and clears).
func checkRunCanaries(installDir string) {
	v := auditRunCanaries(registry.LOCAL_MACHINE, canaryStateDir(installDir))
	if v == "clean" || v == "unplanted" {
		return
	}
	log.Printf("[watch] CANARY: %s", v)
	setProtAlarm("runkey deleter: " + v)
}
