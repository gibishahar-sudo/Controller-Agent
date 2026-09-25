package main

import (
	"os"
	"path/filepath"
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
