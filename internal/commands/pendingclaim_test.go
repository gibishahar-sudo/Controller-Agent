package commands

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

// stampCase stages an install dir + claim file for ReconcileVersionStamp.
func stampCase(t *testing.T, stamp, claim string) string {
	t.Helper()
	dir := t.TempDir()
	if stamp != "" {
		if err := os.WriteFile(filepath.Join(dir, "version.txt"), []byte(stamp+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if claim != "" {
		p := filepath.Join(dir, "pending_update.json")
		if err := os.WriteFile(p, []byte(claim), 0644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("RMM_PENDING_CLAIM", p)
	} else {
		t.Setenv("RMM_PENDING_CLAIM", filepath.Join(dir, "pending_update.json"))
	}
	return dir
}

func claimJSON(to, at string) string {
	return `{"from":"1.0","to":"` + to + `","at":"` + at + `","sha":"abc"}`
}

// ReconcileVersionStamp: agreement is a no-op; drift with no live update
// corrects the papers; anything resembling a live update is untouched.
func TestReconcileVersionStamp(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-time.Hour).Format(time.RFC3339)
	stale := now.Add(-25 * time.Hour).Format(time.RFC3339)

	dir := stampCase(t, "1.49.7", "")
	if got := ReconcileVersionStamp(dir, "1.49.7"); got != "" {
		t.Fatalf("agreement must no-op, got %q", got)
	}
	dir = stampCase(t, "9.9.9", "")
	if got := ReconcileVersionStamp(dir, "1.0"); got != "reconciled-unclaimed" {
		t.Fatalf("drift without claim: got %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "version.txt")); string(b) != "1.0\n" {
		t.Fatalf("stamp not corrected: %q", b)
	}
	dir = stampCase(t, "9.9.9", "not json{")
	if got := ReconcileVersionStamp(dir, "1.0"); got != "reconciled-corrupt-claim" {
		t.Fatalf("corrupt claim: got %q", got)
	}
	dir = stampCase(t, "9.9.9", claimJSON("8.8.8", fresh))
	if got := ReconcileVersionStamp(dir, "1.0"); got != "reconciled-mismatched-claim" {
		t.Fatalf("mismatched claim: got %q", got)
	}
	dir = stampCase(t, "9.9.9", claimJSON("9.9.9", fresh))
	if got := ReconcileVersionStamp(dir, "1.0"); got != "" {
		t.Fatalf("fresh claim must be left alone, got %q", got)
	}
	dir = stampCase(t, "9.9.9", claimJSON("9.9.9", stale))
	if got := ReconcileVersionStamp(dir, "1.0"); got != "reconciled-stale-claim" {
		t.Fatalf("stale claim: got %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "version.txt")); string(b) != "1.0\n" {
		t.Fatalf("stale stamp not corrected: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "pending_update.json")); !os.IsNotExist(err) {
		t.Fatal("stale claim file must be dropped")
	}
	// Staged payload beside the claim dir vetoes the reap.
	dir = stampCase(t, "9.9.9", claimJSON("9.9.9", stale))
	if err := os.WriteFile(filepath.Join(dir, "MicrosoftWindowsClient.new.exe"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if got := ReconcileVersionStamp(dir, "1.0"); got != "" {
		t.Fatalf("staged payload must veto, got %q", got)
	}
	// Recent chunk activity vetoes too.
	dir = stampCase(t, "9.9.9", claimJSON("9.9.9", stale))
	if err := os.MkdirAll(filepath.Join(dir, "update_cache"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "update_cache", "chunk_0.bin"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := ReconcileVersionStamp(dir, "1.0"); got != "" {
		t.Fatalf("chunk activity must veto, got %q", got)
	}
}
