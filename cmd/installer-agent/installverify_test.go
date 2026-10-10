package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// Fresh-start sweep must cover the lock + both pending flags (v1.46.88:
// a leftover delete_pending would teardown the new install on first run,
// a stale agent.lock wedges startup behind the singleton).
func TestStaleSweepFiles(t *testing.T) {
	got := staleSweepFiles()
	want := map[string]bool{"agent.lock": true, "delete_pending.json": true, "delete_pending.json.active": true}
	if len(got) != len(want) {
		t.Fatalf("sweep list = %v, want %v", got, want)
	}
	for _, f := range got {
		if !want[f] {
			t.Fatalf("unexpected sweep entry %q", f)
		}
	}
}

// handshakeWait is the verified-elevation seam (v1.46.89): the parent
// trusts the handoff only when the marker lands in time.
func TestHandshakeWait(t *testing.T) {
	dir := t.TempDir()
	miss := filepath.Join(dir, "nope.ok")
	if handshakeWait(miss, 120*time.Millisecond) {
		t.Fatal("absent marker must time out")
	}
	hit := filepath.Join(dir, "yes.ok")
	go func() {
		time.Sleep(60 * time.Millisecond)
		_ = os.WriteFile(hit, []byte("elevated"), 0644)
	}()
	if !handshakeWait(hit, 5*time.Second) {
		t.Fatal("late marker must be seen")
	}
	if elevatedHandshakePath() == "" && os.Getenv("TEMP") != "" {
		t.Fatal("handshake path must resolve when TEMP is set")
	}
}

// tasklistAgentPIDs pulls PIDs from CSV rows naming our exe (phantoms
// included — classification happens in classifyKillResult).
func TestTasklistAgentPIDs(t *testing.T) {
	out := `"MicrosoftWindowsClient.exe","1234","Console","1","12,000 K"` + "\n" +
		`"svchost.exe","5678","Services","0","10,000 K"` + "\n" +
		`"MICROSOFTWINDOWSCLIENT.EXE","9012","Console","1","9,000 K"` + "\n" +
		"INFO: No tasks are running which match the specified criteria.\n"
	got := tasklistAgentPIDs(out)
	if len(got) != 2 || got[0] != 1234 || got[1] != 9012 {
		t.Fatalf("pids = %v, want [1234 9012]", got)
	}
	if len(tasklistAgentPIDs("")) != 0 {
		t.Fatal("empty input must yield no pids")
	}
}

// classifyKillResult: "no running instance" (dying husks) and SUCCESS
// both mean gone; anything else (denied, errors) means alive.
func TestClassifyKillResult(t *testing.T) {
	for _, dead := range []string{
		`ERROR: The process "MicrosoftWindowsClient.exe" with PID 48584 could not be terminated. Reason: There is no running instance of the task.`,
		"SUCCESS: The process with PID 1234 has been terminated.",
		"sUCCESS: sent termination signal",
	} {
		if classifyKillResult(dead) != killDead {
			t.Fatalf("%q must read dead", dead)
		}
	}
	for _, alive := range []string{
		`ERROR: The process with PID 1234 could not be terminated. Reason: Access is denied.`,
		"",
		"ERROR: Invalid argument.",
	} {
		if classifyKillResult(alive) != killAlive {
			t.Fatalf("%q must read alive", alive)
		}
	}
}

// copyPayloadExe must land exact bytes (v1.46.91: one locked write left
// version.txt stamped new over an old exe). Failure surfaces the cause.
func TestCopyPayloadExe(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "MicrosoftWindowsClient.exe")
	payload := []byte("fake-agent-bytes-1234567890")
	if err := copyPayloadExe(dst, payload, 2); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := checkFileSHA(dst, payload, "test"); err != nil {
		t.Fatalf("verify after copy: %v", err)
	}
	bad := filepath.Join(dir, "no-such-dir", "x.exe")
	if err := copyPayloadExe(bad, payload, 1); err == nil {
		t.Fatal("unwritable destination must error (rounds=1: no sleep)")
	}
}

// wmiTermCmd must name the exact PID, single-call form (v1.47.5: the
// installer escalation for processes taskkill calls nonexistent).
func TestWmiTermCmd(t *testing.T) {
	got := wmiTermCmd(48584)
	want := `(Get-CimInstance Win32_Process -Filter "ProcessId=48584" | Invoke-CimMethod -MethodName Terminate).ReturnValue`
	if got != want {
		t.Fatalf("cmd = %q", got)
	}
}
