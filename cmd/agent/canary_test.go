package main

import (
	"strings"
	"testing"
)

// Verdict matrix: presence of (oursA, oursB, pattern, random).
func TestCanaryVerdict(t *testing.T) {
	cases := []struct {
		a, b, p, r bool
		want       string
	}{
		{true, true, true, true, "clean"},
		{true, true, false, false, "clean"},   // ours present: canary loss never alarms
		{true, false, true, true, "surgical"}, // partial ours + canaries
		{false, false, false, true, "targeted"},
		{false, false, false, false, "bulk"},
		{false, false, true, true, "surgical"},
		{true, false, false, false, "bulk"}, // partial ours, nothing else: bulk pattern
	}
	for _, c := range cases {
		if got := canaryVerdict(c.a, c.b, c.p, c.r); got != c.want {
			t.Fatalf("(%v,%v,%v,%v) = %q want %q", c.a, c.b, c.p, c.r, got, c.want)
		}
	}
}

// Random name is stable across calls, well-formed, and persists.
func TestCanaryRandomNameStable(t *testing.T) {
	dir := t.TempDir()
	n1, isNew := canaryRandomName(dir)
	if n1 == "" || !isNew {
		t.Fatalf("first call must generate: %q %v", n1, isNew)
	}
	n2, isNew := canaryRandomName(dir)
	if n2 != n1 || isNew {
		t.Fatalf("second call must reload: %q %v", n2, isNew)
	}
	if canonCanaryName(n1+"junk") != "" || canonCanaryName("WindowsUpdate") != "" {
		t.Fatal("malformed names must reject")
	}
}

// Inert command must never allocate a console or do work.
func TestCanaryInertCmd(t *testing.T) {
	if canaryInertCmd == "" {
		t.Fatal("inert command must be set")
	}
	lowered := strings.ToLower(canaryInertCmd)
	for _, bad := range []string{"cmd.exe", "powershell", ".bat", ".ps1", ".vbs"} {
		if strings.Contains(lowered, bad) {
			t.Fatalf("inert command must not spawn consoles/scripts: %q", canaryInertCmd)
		}
	}
}
