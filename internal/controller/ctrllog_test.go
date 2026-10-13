package controller

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Startup marker lands in a fresh log file.
func TestSetupControllerLogMarker(t *testing.T) {
	dir := t.TempDir()
	old := ctrlExeDirOverride
	ctrlExeDirOverride = dir
	defer func() { ctrlExeDirOverride = old }()
	stop := SetupControllerLog("testapp", "9.9.9", "unittest")
	stop("test-done")
	b, err := os.ReadFile(filepath.Join(dir, "controller.log"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "testapp 9.9.9 starting") || !strings.Contains(s, "stopping: test-done") {
		t.Fatalf("markers missing:\n%s", s)
	}
}

// Oversized log rotates to .1 on setup.
func TestSetupControllerLogRotates(t *testing.T) {
	dir := t.TempDir()
	old := ctrlExeDirOverride
	ctrlExeDirOverride = dir
	defer func() { ctrlExeDirOverride = old }()
	big := make([]byte, ctrlLogMaxBytes+1024)
	if err := os.WriteFile(filepath.Join(dir, "controller.log"), big, 0644); err != nil {
		t.Fatal(err)
	}
	stop := SetupControllerLog("testapp", "9.9.9", "unittest")
	stop("done")
	st, err := os.Stat(filepath.Join(dir, "controller.log.1"))
	if err != nil || st.Size() != int64(len(big)) {
		t.Fatalf("backup missing/wrong: %v", err)
	}
	cur, err := os.Stat(filepath.Join(dir, "controller.log"))
	if err != nil || cur.Size() > 65536 {
		t.Fatalf("fresh log wrong: %v", err)
	}
}

// LogCrash logs the panic (stack included) and re-panics the same value.
func TestLogCrashPropagates(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("panic value changed: %v", r)
			}
		}()
		defer LogCrash("testapp")
		panic("boom")
	}()
	if !strings.Contains(buf.String(), "FATAL PANIC") || !strings.Contains(buf.String(), "boom") {
		t.Fatalf("panic not logged:\n%s", buf.String())
	}
}
