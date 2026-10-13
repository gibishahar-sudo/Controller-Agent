package commands

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// SMB failures classify into actionable words (never bare errors).
func TestClassifySMBErr(t *testing.T) {
	mk := func(errno int) error {
		return &os.PathError{Op: "open", Path: `\\h\ADMIN$`, Err: syscall.Errno(errno)}
	}
	cases := []struct {
		err  error
		want string
	}{
		{mk(5), "access denied"},
		{mk(53), "bad network path"},
		{mk(1219), "IPC$"},
		{mk(1231), "unreachable"},
		{mk(64), "went away"},
		{mk(9999), "os error 9999"},
	}
	for _, c := range cases {
		if got := classifySMBErr(c.err); !strings.Contains(got, c.want) {
			t.Fatalf("classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// WMI ReturnValues translate to human causes.
func TestWmiReturnText(t *testing.T) {
	cases := map[string]string{"0": "ok", "2": "access denied", "3": "privilege", "8": "unknown failure", "9": "path not found", "21": "invalid parameter", "99": "99"}
	for code, want := range cases {
		if got := wmiReturnText(code); !strings.Contains(got, want) {
			t.Fatalf("wmi %q = %q, want %q", code, got, want)
		}
	}
}

// Terminal detail propagates: ledger stores the reason, lookup serves it.
func TestCloneTerminalDetail(t *testing.T) {
	resetCloneState()
	oldExec := nmsCloneExec
	t.Cleanup(func() { nmsCloneExec = oldExec })
	nmsCloneExec = func(host, ver string) (string, string) {
		return "copy-failed", "smb copy: access denied (SMB creds lack ADMIN$ write)"
	}
	st, started := startCloneJob("192.0.2.80", "1.49.10", false)
	if !started || st != "cloning" {
		t.Fatalf("start: %q %v", st, started)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		cloneMu.Lock()
		j, ok := cloneJobs["192.0.2.80"]
		cloneMu.Unlock()
		if ok && j.Done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job never completed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, detail, ok := cloneJobLookup("192.0.2.80")
	if !ok || got != "copy-failed" || !strings.Contains(detail, "access denied") {
		t.Fatalf("ledger: %q %q %v", got, detail, ok)
	}
	cloneMu.Lock()
	if cloneJobs["192.0.2.80"].Forced {
		cloneMu.Unlock()
		t.Fatal("non-force path must never flag forced")
	}
	cloneMu.Unlock()
	if _, _, ok := cloneJobLookup("192.0.2.81"); ok {
		t.Fatal("unknown host must miss")
	}
}

// Dry-run writes nothing and reports every gate: unreachable, managed,
// ineligible, no-payload, hidden temp, and the happy path.
func TestCloneDryRun(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, Subnets: nil, AutoClone: false})
	oldDial, oldRead, oldStat := dialTCP, nmsReadUNC, nmsDirStat
	t.Cleanup(func() { dialTCP, nmsReadUNC, nmsDirStat = oldDial, oldRead, oldStat })

	dialTCP = func(string, int, time.Duration) bool { return false }
	if out := CloneDryRun("192.0.2.90", nil); !strings.Contains(out, "WOULD NOT CLONE (unreachable)") {
		t.Fatalf("dead host:\n%s", out)
	}
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return []byte("1.49.10"), nil }
	if out := CloneDryRun("192.0.2.91", nil); !strings.Contains(out, "already managed") {
		t.Fatalf("managed host:\n%s", out)
	}
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	if out := CloneDryRun("192.0.2.92", nil); !strings.Contains(out, "WOULD NOT CLONE (no-payload)") {
		t.Fatalf("no payload:\n%s", out)
	}
	payload := make([]byte, 10*1024*1024)
	payload[0], payload[1] = 'M', 'Z'
	if err := os.WriteFile(NMSInstallerPath(), payload, 0644); err != nil {
		t.Fatal(err)
	}
	nmsDirStat = func(string) bool { return false }
	if out := CloneDryRun("192.0.2.93", nil); !strings.Contains(out, "NOT visible") {
		t.Fatalf("hidden temp:\n%s", out)
	}
	nmsDirStat = func(string) bool { return true }
	if out := CloneDryRun("192.0.2.94", nil); !strings.Contains(out, "WOULD CLONE") {
		t.Fatalf("happy path:\n%s", out)
	}
	// The verb routes --dry-run without side effects.
	res, err := NMSHandle("nms-clone", "192.0.2.94 --dry-run", nil)
	if err != nil || !strings.Contains(res, "dry-run 192.0.2.94") {
		t.Fatalf("verb: %q %v", res, err)
	}
}

// --force needs --confirm YES alongside it: force alone, or YES alone,
// still refuses. Both present on an unknown host starts a FORCED job.
func TestCloneForceMatrix(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	resetCloneState()
	oldDial, oldRead, oldExec := dialTCP, nmsReadUNC, nmsCloneExec
	t.Cleanup(func() { dialTCP, nmsReadUNC, nmsCloneExec = oldDial, oldRead, oldExec })
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrPermission }
	nmsCloneExec = func(host, ver string) (string, string) { return "copy-failed", "test" }

	if _, err := NMSHandle("nms-clone", "192.0.2.95 --force", nil); err == nil ||
		!strings.Contains(err.Error(), "--confirm YES") {
		t.Fatalf("force without confirm must refuse naming confirm, got %v", err)
	}
	if _, err := NMSHandle("nms-clone", "192.0.2.95 YES", nil); err == nil ||
		!strings.Contains(err.Error(), "verify access first") {
		t.Fatalf("YES without --force must take the normal refusal, got %v", err)
	}
	res, err := NMSHandle("nms-clone", "192.0.2.95 --force --confirm YES", nil)
	if err != nil || !strings.Contains(res, "FORCED") {
		t.Fatalf("force+confirm must start audited job, got %q %v", res, err)
	}
	cloneMu.Lock()
	j, ok := cloneJobs["192.0.2.95"]
	cloneMu.Unlock()
	if !ok || !j.Forced {
		t.Fatalf("ledger must flag the job forced: %+v %v", j, ok)
	}
	// Force never bypasses the other gates: unreachable still refuses.
	dialTCP = func(string, int, time.Duration) bool { return false }
	if _, err := NMSHandle("nms-clone", "192.0.2.96 --force --confirm YES", nil); err == nil ||
		!strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("force on dead host must refuse, got %v", err)
	}
	// Force never bypasses proven-managed either.
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return []byte("1.49.10"), nil }
	if _, err := NMSHandle("nms-clone", "192.0.2.97 --force --confirm YES", nil); err == nil ||
		!strings.Contains(err.Error(), "already managed") {
		t.Fatalf("force on managed host must refuse, got %v", err)
	}
}
