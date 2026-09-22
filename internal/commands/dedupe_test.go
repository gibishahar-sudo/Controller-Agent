package commands

import "testing"

// Same id twice: second run must be suppressed (two-controller dedupe).
func TestExecuteCheckedDedupe(t *testing.T) {
	id := "test-dedupe-id-1"
	r1, s1, err1 := ExecuteChecked(id, "get-hostname", "")
	if err1 != nil || s1 || r1 == "" {
		t.Fatalf("first run should execute: r=%q suppressed=%v err=%v", r1, s1, err1)
	}
	r2, s2, err2 := ExecuteChecked(id, "get-hostname", "")
	if err2 != nil || !s2 || r2 != "" {
		t.Fatalf("second run should suppress: r=%q suppressed=%v err=%v", r2, s2, err2)
	}
}

// Empty id always runs (old controllers).
func TestExecuteCheckedNoID(t *testing.T) {
	if _, s, _ := ExecuteChecked("", "get-hostname", ""); s {
		t.Fatalf("empty id must never suppress")
	}
	if _, s, _ := ExecuteChecked("", "get-hostname", ""); s {
		t.Fatalf("empty id must never suppress twice")
	}
}
