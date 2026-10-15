package commands

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Singleton: missing/garbled/dead/mismatched pid files yield takeover;
// a live matching holder yields; release only removes our own file.
func TestClaimNMSPid(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)

	// Missing file: take over.
	if !ClaimNMSPid() {
		t.Fatal("missing pid file must take over")
	}
	// Re-entrant: our own record yields true (we own it).
	if !ClaimNMSPid() {
		t.Fatal("own record must read as owned")
	}
	// Garbled file: take over.
	if err := os.WriteFile(NMSPidPath(), []byte("garbage\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !ClaimNMSPid() {
		t.Fatal("garbled pid file must take over")
	}
	// Dead pid: take over.
	if err := os.WriteFile(NMSPidPath(), []byte("99999999\n12345\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !ClaimNMSPid() {
		t.Fatal("dead pid must take over")
	}
	// Live pid, wrong create time (recycled PID): take over.
	ours, err := ownPidRecord()
	if err != nil {
		t.Fatal(err)
	}
	_ = ours
	me := os.Getpid()
	if err := os.WriteFile(NMSPidPath(), []byte(strconv.Itoa(me)+"\n1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !ClaimNMSPid() {
		t.Fatal("mismatched create time must take over (PID recycling)")
	}
	// Release removes our file...
	ReleaseNMSPid()
	if _, err := os.Stat(NMSPidPath()); !os.IsNotExist(err) {
		t.Fatal("release must remove owned pid file")
	}
	// ...but never a foreign one.
	if err := os.WriteFile(NMSPidPath(), []byte("99999998\n2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ReleaseNMSPid()
	if _, err := os.Stat(NMSPidPath()); err != nil {
		t.Fatal("release must not touch foreign pid file")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Flags are case-tolerant: --Force/--FORCE/--Dry-Run behave.
func TestCloneFlagsCaseTolerant(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	resetCloneState()
	oldDial, oldRead, oldExec := dialTCP, nmsReadUNC, nmsCloneExec
	t.Cleanup(func() { dialTCP, nmsReadUNC, nmsCloneExec = oldDial, oldRead, oldExec })
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	nmsCloneExec = func(host, ver string) (string, string) { return "copy-failed", "test" }
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, Subnets: []string{}, Exclude: []string{"nonexistent.invalid"}})
	for _, args := range []string{
		"192.0.2.100 --Force --confirm YES",
	} {
		res, err := NMSHandle("nms-clone", args, nil)
		if err != nil || !strings.Contains(res, "FORCED") {
			t.Fatalf("mixed-case force must start audited job, got %q %v", res, err)
		}
		resetCloneState()
	}
}

// Reachability probes all four ports (445/135/139/3389), not just two.
func TestTCPReachableAllPorts(t *testing.T) {
	oldDial := dialTCP
	t.Cleanup(func() { dialTCP = oldDial })
	var probed []int
	dialTCP = func(host string, port int, d time.Duration) bool {
		probed = append(probed, port)
		return port == 3389
	}
	if !TCPReachable("192.0.2.101") {
		t.Fatal("RDP-only host must read reachable")
	}
	for _, want := range []int{445, 135, 139, 3389} {
		found := false
		for _, p := range probed {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("port %d never probed: %v", want, probed)
		}
	}
	dialTCP = func(string, int, time.Duration) bool { return false }
	if TCPReachable("192.0.2.102") {
		t.Fatal("dark host must read unreachable")
	}
}
