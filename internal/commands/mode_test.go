package commands

import (
	"os"
	"path/filepath"
	"testing"
)

// SetAgentMode persists atomically and reads back exactly.
func TestSetAgentModeRoundTrip(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no exe path")
	}
	path := filepath.Join(filepath.Dir(exe), "mode.json")
	raw, _ := os.ReadFile(path)
	defer func() {
		if raw == nil {
			_ = os.Remove(path)
		} else {
			_ = os.WriteFile(path, raw, 0644)
		}
	}()
	res, err := SetAgentMode("stealth")
	if err != nil {
		t.Fatal(err)
	}
	if res == "" {
		t.Fatal("empty result")
	}
	if got := AgentMode(); got != ModeStealth {
		t.Fatalf("AgentMode = %q, want stealth", got)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "stealth\n" {
		t.Fatalf("mode.json = %q, want stealth newline-terminated", b)
	}
}

// Unknown modes are rejected and never persisted.
func TestSetAgentModeRejects(t *testing.T) {
	if _, err := SetAgentMode("nope"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	for _, m := range ValidModes {
		if !IsValidMode(m) {
			t.Fatalf("valid mode %q rejected", m)
		}
	}
}
