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
