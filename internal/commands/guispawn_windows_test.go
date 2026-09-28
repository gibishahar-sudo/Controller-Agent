//go:build windows

package commands

import (
	"os"
	"strings"
	"testing"
)

// spawnGUI must preserve exit-code semantics on both its paths
// (explicit desktop and plain-hidden fallback).
func TestSpawnGUIExitCodes(t *testing.T) {
	gp, err := spawnGUI("cmd.exe", []string{"/c", "exit 0"}, nil, nil)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	if gp.Pid() <= 0 {
		t.Fatal("bad pid")
	}
	if err := gp.Wait(); err != nil {
		t.Fatalf("exit 0 returned %v", err)
	}
	gp, err = spawnGUI("cmd.exe", []string{"/c", "exit 3"}, nil, nil)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	if err := gp.Wait(); err == nil || !strings.Contains(err.Error(), "3") {
		t.Fatalf("exit 3 returned %v, want exit status 3", err)
	}
}

func TestSpawnGUIMissing(t *testing.T) {
	if _, err := spawnGUI(`C:\definitely\not\here.exe`, nil, nil, nil); err == nil {
		t.Fatal("missing binary should error")
	}
}

func TestProcAlive(t *testing.T) {
	if !procAlive(os.Getpid()) {
		t.Fatal("own process should be alive")
	}
	if procAlive(0) || procAlive(-1) {
		t.Fatal("non-pids must not be alive")
	}
	// Absurd pid: either absent (false) or, on true 64-bit overflow
	// wraparound, still deterministic — just require no crash.
	_ = procAlive(1 << 30)
}
