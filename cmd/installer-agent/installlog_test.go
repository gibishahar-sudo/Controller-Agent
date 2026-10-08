package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The run log must capture log.Fatalf-class lines to disk: silent installs
// show nothing, so a failed run was indistinguishable from a stale box.
func TestSetupInstallLogCaptures(t *testing.T) {
	// NOTE: plain dir, not t.TempDir — the log handle stays open for the
	// process lifetime by design, and Windows refuses to delete open files.
	dir := filepath.Join(os.TempDir(), "rmminstalllogtest")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEMP", dir)
	defer log.SetOutput(os.Stderr)
	setupInstallLog()
	log.Printf("install-log-probe-%d", 4242)
	b, err := os.ReadFile(filepath.Join(dir, "rmm-install.log"))
	if err != nil {
		t.Fatalf("log file missing: %v", err)
	}
	if !strings.Contains(string(b), "install-log-probe-4242") {
		t.Fatalf("probe line absent: %q", b)
	}
}

// Missing TEMP must not break anything and must not spray real system
// dirs (v1.46.91: this test wrote the live C:\Windows\Temp log twice).
// Plain dir like Captures (t.TempDir auto-cleanup chokes on the open
// handle, which stays open for the process lifetime by design).
func TestSetupInstallLogNoTemp(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "rmminstalllognotemp")
	_ = os.MkdirAll(dir, 0755)
	t.Setenv("TEMP", "")
	t.Setenv("RMM_LOG_DIR", dir)
	defer log.SetOutput(os.Stderr)
	setupInstallLog()
	log.Printf("noop")
	if b, err := os.ReadFile(filepath.Join(dir, "rmm-install.log")); err != nil || !strings.Contains(string(b), "noop") {
		t.Fatalf("override dir must capture the line: %v %q", err, b)
	}
}
