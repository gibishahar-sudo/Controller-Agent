package main

import (
	"os"
	"path/filepath"
	"testing"
)

// v1.49.25 post-mortom: "install exe unwritable after retries ... being used
// by another process" on a box whose holder sweep had just come back clean.
// WMI resurrection (timer + death trigger) and the NMS guard arm relaunch the
// agent within a second of it dying, and a live image re-locks the file - so
// retrying the write alone can never win. The unlock callback must run before
// every retry round.
func TestCopyPayloadExeUnlocksBetweenRounds(t *testing.T) {
	// Unwritable destination: every round fails, so the callback must fire
	// on each retry (rounds-1 times), never on the first attempt.
	calls := 0
	bad := filepath.Join(t.TempDir(), "no-such-dir", "agent.exe")
	if err := copyPayloadExe(bad, []byte("x"), 4, func() { calls++ }); err == nil {
		t.Fatal("unwritable destination must fail")
	}
	if calls != 3 {
		t.Fatalf("unlock must run before each of the 3 retries, got %d", calls)
	}

	// A clean first write must not pay for the callback at all.
	dst := filepath.Join(t.TempDir(), "agent.exe")
	calls = 0
	if err := copyPayloadExe(dst, []byte("payload-bytes"), 4, func() { calls++ }); err != nil {
		t.Fatalf("clean write must succeed: %v", err)
	}
	if calls != 0 {
		t.Fatalf("no retry means no unlock, got %d", calls)
	}
	if b, _ := os.ReadFile(dst); string(b) != "payload-bytes" {
		t.Fatalf("exact bytes must land, got %q", string(b))
	}
}

// nil callback stays legal (the old call shape) so no path can panic on it.
func TestCopyPayloadExeNilUnlockOK(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "agent.exe")
	if err := copyPayloadExe(dst, []byte("bytes"), 2, nil); err != nil {
		t.Fatalf("nil unlock must be accepted: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "missing", "agent.exe")
	if err := copyPayloadExe(bad, []byte("bytes"), 2, nil); err == nil {
		t.Fatal("unwritable destination must still fail with nil unlock")
	}
}
