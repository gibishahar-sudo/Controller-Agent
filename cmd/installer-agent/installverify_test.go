package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tasklistHasAgent parses tasklist CSV for our binary (v1.46.51: the
// kill-verify gate depends on it — a missed survivor holds the exe
// locked and the install below fails silently into a downgrade).
func TestTasklistHasAgent(t *testing.T) {
	hit := `"MicrosoftWindowsClient.exe","1234","Console","1","12,000 K"` + "\n"
	if !tasklistHasAgent(hit) {
		t.Fatal("CSV hit not detected")
	}
	if !tasklistHasAgent(strings.ToLower(hit)) {
		t.Fatal("case-insensitive miss")
	}
	for _, miss := range []string{
		"",
		"INFO: No tasks are running which match the specified criteria.\n",
		`"svchost.exe","1234","Services","0","10,000 K"` + "\n",
		`"MicrosoftWindowsClient.exe.bak","1","Console","1","1 K"` + "\n",
	} {
		if tasklistHasAgent(miss) {
			t.Fatalf("false positive on %q", miss)
		}
	}
}

// checkFileSHA catches short/legacy writes and missing files without
// exiting (the installer wraps it in a fatal).
func TestCheckFileSHA(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.bin")
	want := []byte("payload-bytes-12345")
	if err := os.WriteFile(p, want, 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkFileSHA(p, want, "test"); err != nil {
		t.Fatalf("match rejected: %v", err)
	}
	if err := checkFileSHA(p, []byte("other"), "test"); err == nil {
		t.Fatal("mismatch accepted")
	}
	if err := checkFileSHA(filepath.Join(dir, "nope.bin"), want, "test"); err == nil {
		t.Fatal("missing accepted")
	}
}

func TestCheckVersionFile(t *testing.T) {
	dir := t.TempDir()
	if err := checkVersionFile(dir, "1.46.51", "test"); err == nil {
		t.Fatal("missing version.txt accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "version.txt"), []byte("1.46.51\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := checkVersionFile(dir, "1.46.51", "test"); err != nil {
		t.Fatalf("match rejected: %v", err)
	}
	if err := checkVersionFile(dir, "9.9.9", "test"); err == nil {
		t.Fatal("wrong version accepted")
	}
}
