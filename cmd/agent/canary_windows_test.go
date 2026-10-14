//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// Registry IO against an HKCU sandbox (medium-integrity writable).
func withCanarySandbox(t *testing.T) {
	t.Helper()
	old := canaryRunPath
	canaryRunPath = `Software\RMMTestCanary\Run`
	t.Cleanup(func() { canaryRunPath = old })
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\RMMTestCanary\Run`)
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, `Software\RMMTestCanary\Run`) })
}

func writeRunVal(t *testing.T, name, val string) {
	t.Helper()
	k, _, err := registry.CreateKey(registry.CURRENT_USER, canaryRunPath, registry.WRITE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if err := k.SetStringValue(name, val); err != nil {
		t.Fatal(err)
	}
}

func delRunVal(t *testing.T, name string) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, canaryRunPath, registry.WRITE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	_ = k.DeleteValue(name)
}

// First sight baits silently, second sight verdicts.
func TestCanaryAuditFlow(t *testing.T) {
	withCanarySandbox(t)
	dir := t.TempDir()
	writeRunVal(t, "WindowsUpdate", "x")
	writeRunVal(t, "WindowsUpdateWatchdog", "y")
	if got := auditRunCanaries(registry.CURRENT_USER, dir); got != "unplanted" {
		t.Fatalf("first sight must plant silently, got %q", got)
	}
	if got := auditRunCanaries(registry.CURRENT_USER, dir); got != "clean" {
		t.Fatalf("intact box must read clean, got %q", got)
	}
	// Pattern + ours deleted, random survives: targeted.
	delRunVal(t, "WindowsUpdate")
	delRunVal(t, "WindowsUpdateWatchdog")
	delRunVal(t, canaryPatternName)
	if got := auditRunCanaries(registry.CURRENT_USER, dir); !strings.HasPrefix(got, "targeted") {
		t.Fatalf("must verdict targeted, got %q", got)
	}
}

// Bulk wipe verdict.
func TestCanaryAuditBulk(t *testing.T) {
	withCanarySandbox(t)
	dir := t.TempDir()
	writeRunVal(t, "WindowsUpdate", "x")
	writeRunVal(t, "WindowsUpdateWatchdog", "y")
	if got := auditRunCanaries(registry.CURRENT_USER, dir); got != "unplanted" {
		t.Fatalf("first sight: %q", got)
	}
	for _, n := range []string{"WindowsUpdate", "WindowsUpdateWatchdog", canaryPatternName} {
		delRunVal(t, n)
	}
	// Random canary by exact name from the state file (no enumeration games).
	b, err := os.ReadFile(filepath.Join(dir, "canaryname.txt"))
	if err != nil {
		t.Fatal(err)
	}
	delRunVal(t, strings.TrimSpace(string(b)))
	if got := auditRunCanaries(registry.CURRENT_USER, dir); !strings.HasPrefix(got, "bulk") {
		t.Fatalf("must verdict bulk, got %q", got)
	}
}
