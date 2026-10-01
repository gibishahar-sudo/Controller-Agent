package commands

import (
	"os"
	"path/filepath"
	"testing"
)

// PendingClaim honors RMM_PENDING_CLAIM (tests + custom layouts) and
// rejects malformed claims. The watcher leans on this to tell verified
// installs from trojan swaps.
func TestPendingClaimEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pending_update.json")
	claim := `{"from":"1.46.50","to":"1.46.51","sha":"abc123"}`
	if err := os.WriteFile(p, []byte(claim), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RMM_PENDING_CLAIM", p)
	to, sha, _, ok := PendingClaim()
	if !ok || to != "1.46.51" || sha != "abc123" {
		t.Fatalf("got to=%q sha=%q ok=%v", to, sha, ok)
	}
	if err := os.WriteFile(p, []byte("not json{"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := PendingClaim(); ok {
		t.Fatal("malformed claim accepted")
	}
	// Missing file: not ok (never errors, never panics).
	t.Setenv("RMM_PENDING_CLAIM", filepath.Join(dir, "nope.json"))
	if _, _, _, ok := PendingClaim(); ok {
		t.Fatal("missing claim file accepted")
	}
}
