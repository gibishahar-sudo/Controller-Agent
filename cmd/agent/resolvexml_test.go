//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// resolveTaskXML prefers the install dir, then falls back to any backup
// copy (the v1.44.0 shadowing fix: a single-dir wipe must not blind it).
func TestResolveTaskXMLShadowing(t *testing.T) {
	install := t.TempDir()
	// Distinctive name: systemBackupDirs scans the real C:\Users, so the
	// fixture must not collide with any genuine task XML on the box.
	// (Only the install dir is asserted: backup dirs are environment.)
	name := "rmm-test-only-7f3a-task.xml"
	// Missing everywhere must return "".
	if got := resolveTaskXML(install, name); got != "" {
		t.Fatalf("expected empty with no copies, got %q", got)
	}
	if err := os.WriteFile(filepath.Join(install, name), []byte("<task/>"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := resolveTaskXML(install, name); got != filepath.Join(install, name) {
		t.Fatalf("install-dir copy not preferred, got %q", got)
	}
}
