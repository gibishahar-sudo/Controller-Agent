package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// backupVerified: legacy copies (no manifest) are accepted, matching
// manifests pass, mismatched manifests refuse.
func TestBackupVerified(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "MicrosoftWindowsClient.exe")
	if err := os.WriteFile(exe, []byte("fake-binary-bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	if !backupVerified(exe) {
		t.Fatal("legacy copy without manifest refused (must accept)")
	}
	writeBackupManifest(dir, "1.44.1", exe)
	if !backupVerified(exe) {
		t.Fatal("matching manifest refused")
	}
	if err := os.WriteFile(exe, []byte("trojan-bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	if backupVerified(exe) {
		t.Fatal("mismatched manifest accepted (must refuse)")
	}
}

// backupMismatch is true only for proven mismatch (present, parseable,
// non-empty sha, differing bytes) — never for legacy or corrupt states.
func TestBackupMismatchTriState(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "MicrosoftWindowsClient.exe")
	if err := os.WriteFile(exe, []byte("fake-binary-bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	if backupMismatch(exe) {
		t.Fatal("legacy copy flagged mismatch")
	}
	writeBackupManifest(dir, "1.44.1", exe)
	if backupMismatch(exe) {
		t.Fatal("matching copy flagged mismatch")
	}
	if err := os.WriteFile(exe, []byte("trojan-bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	if !backupMismatch(exe) {
		t.Fatal("proven mismatch not flagged")
	}
	if err := os.WriteFile(filepath.Join(dir, "integrity.json"), []byte("not json{"), 0644); err != nil {
		t.Fatal(err)
	}
	if backupMismatch(exe) {
		t.Fatal("corrupt manifest flagged mismatch (must fail open)")
	}
}

// quarantineBadBackup moves the file aside (forensics preserved) and
// returns the new path; missing files fail gracefully.
func TestQuarantineBadBackup(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "MicrosoftWindowsClient.exe")
	if err := os.WriteFile(exe, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	q := quarantineBadBackup(exe)
	if q == "" {
		t.Fatal("quarantine returned empty path")
	}
	if _, err := os.Stat(exe); !os.IsNotExist(err) {
		t.Fatal("original still present after quarantine")
	}
	if _, err := os.Stat(q); err != nil {
		t.Fatalf("quarantined copy missing: %v", err)
	}
	if quarantineBadBackup(filepath.Join(dir, "nope.exe")) != "" {
		t.Fatal("missing file quarantined")
	}
}

// writeFileAtomic round-trips content and leaves no temp droppings.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.bin")
	if err := writeFileAtomic(p, []byte("payload"), 0755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "payload" {
		t.Fatalf("round trip = %q, %v", b, err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "x.bin" {
			t.Fatalf("temp dropping left behind: %s", e.Name())
		}
	}
}

// Claim-match converges FORWARD (v1.46.51 post-mortem): a poisoned
// backup slot (old bytes under fresh papers, e.g. a failed refresh
// during install) must never overwrite a healthy pinned install.
// The trojan path (installed matches neither pin nor backup) is
// intentionally not executed here — it kills live agent processes.
func TestVerifyBinaryConvergesForward(t *testing.T) {
	newBytes := []byte("agent-1.46.51-fresh-bytes")
	oldBytes := []byte("agent-1.46.49-stale-bytes")
	const ver = "1.46.51"

	installDir := t.TempDir()
	agentPath := filepath.Join(installDir, "MicrosoftWindowsClient.exe")
	if err := os.WriteFile(agentPath, newBytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "version.txt"), []byte(ver+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	backupDir := t.TempDir()
	backupAgent := filepath.Join(backupDir, "MicrosoftWindowsClient.exe")
	if err := os.WriteFile(backupAgent, oldBytes, 0755); err != nil {
		t.Fatal(err)
	}
	// pickBackup needs the cert sibling beside every binary.
	backupCert := filepath.Join(backupDir, "server.crt")
	if err := os.WriteFile(backupCert, []byte("fake-cert"), 0644); err != nil {
		t.Fatal(err)
	}
	// Fresh papers over stale bytes, no manifest (legacy slot): the
	// exact shape a failed installer refresh leaves behind.
	if err := os.WriteFile(filepath.Join(backupDir, "version.txt"), []byte(ver+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	backupDir2 := t.TempDir() // absent slot: restoreBinary's re-sync owns it, not converge

	claimDir := t.TempDir()
	newSHA := fileHash(agentPath)
	claim := `{"from":"1.46.49","to":"` + ver + `","sha":"` + newSHA + `"}`
	if err := os.WriteFile(filepath.Join(claimDir, "pending_update.json"), []byte(claim), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RMM_PENDING_CLAIM", filepath.Join(claimDir, "pending_update.json"))

	w := &watchCfg{
		agentPath:   agentPath,
		installDir:  installDir,
		backupDir:   backupDir,
		backupAgent: backupAgent,
		backupCert:  backupCert,
		backupDir2:  backupDir2,
		backupAgent2: filepath.Join(backupDir2, "MicrosoftWindowsClient.exe"),
	}
	w.verifyBinary()

	if got, _ := os.ReadFile(agentPath); string(got) != string(newBytes) {
		t.Fatalf("installed binary touched (downgraded?): %q", got)
	}
	if got, _ := os.ReadFile(backupAgent); string(got) != string(newBytes) {
		t.Fatalf("stale backup not converged forward: %q", got)
	}
	// Fresh manifest pins the converged bytes (quarantine-proof).
	raw, err := os.ReadFile(filepath.Join(backupDir, "integrity.json"))
	if err != nil || !strings.Contains(string(raw), newSHA) {
		t.Fatalf("no fresh manifest for converged backup: %q, %v", raw, err)
	}
}

// Corrupt manifests fail open (never brick old installs).
func TestBackupVerifiedCorruptManifest(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "MicrosoftWindowsClient.exe")
	if err := os.WriteFile(exe, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "integrity.json"), []byte("not json{"), 0644); err != nil {
		t.Fatal(err)
	}
	if !backupVerified(exe) {
		t.Fatal("corrupt manifest refused (must fail open)")
	}
}
