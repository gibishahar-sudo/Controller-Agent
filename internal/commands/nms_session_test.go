package commands

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// net-use parser: OK/disconnected/ghost lines, headers, noise.
func TestParseNetUseShares(t *testing.T) {
	out := `New connections will be remembered.


Status       Local     Remote                    Network
-------------------------------------------------------------------------------
OK           Z:        \\SRV\share               Microsoft Windows Network
Disconnected           \\HOST\ADMIN$             Microsoft Windows Network
             \\host\c$                           Microsoft Windows Network
The command completed successfully.
`
	got := parseNetUseShares(out)
	want := map[string]bool{`\\SRV\share`: true, `\\HOST\ADMIN$`: true, `\\host\c$`: true}
	if len(got) != len(want) {
		t.Fatalf("shares = %q", got)
	}
	for _, s := range got {
		if !want[s] {
			t.Fatalf("unexpected share %q", s)
		}
	}
	if len(parseNetUseShares("garbage\n\nno backslash here\n")) != 0 {
		t.Fatal("noise must parse empty")
	}
}

// Host filter is case-insensitive prefix on \\host\.
func TestHostShares(t *testing.T) {
	shares := []string{`\\H\C$`, `\\h\ADMIN$`, `\\other\x$`, `Z:`}
	got := hostShares(shares, "h")
	if len(got) != 2 {
		t.Fatalf("host filter = %q", got)
	}
	if len(hostShares(shares, "zzz")) != 0 {
		t.Fatal("unknown host must miss")
	}
}

// PS error text maps onto the same words as the Go errno table.
func TestClassifyPSNetErr(t *testing.T) {
	cases := map[string]string{
		"Access is denied":               "access denied",
		"0x80070005 oops":                "access denied",
		"network path was not found":     "bad network path",
		"1319? no: 1219 happened":        "IPC$",
		"timed out waiting":              "stalled",
		"":                               "no detail",
		"weird unique failure 987654321": "weird unique failure",
	}
	for in, want := range cases {
		if got := classifyPSNetErr(in); !strings.Contains(got, want) {
			t.Fatalf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

// Session script: vault cred file path in, no secret out; drive established
// and referenced; UNC paths for I/O (never the drive letter).
func TestSmbSessionScript(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	s := smbSessionScript("192.0.2.5")
	for _, want := range []string{"New-PSDrive", "-Credential", "SESSION-OK", "nms-wmi-cred", "192.0.2.5"} {
		if !strings.Contains(s, want) {
			t.Fatalf("session script missing %q", want)
		}
	}
}

// Cred CIM script: DCOM + session + credential wiring, no secret.
func TestCimCreateCredScript(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	s := cimCreateCredScript("h", "cmd")
	for _, want := range []string{
		"New-CimSessionOption -Protocol Dcom",
		"-SessionOption $opt",
		"Invoke-CimMethod -CimSession $s",
		"PSCredential",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("cred script missing %q", want)
		}
	}
}

// Identity memory: pin, recall, forget. Case-insensitive host keys.
func TestHostIdentityMemory(t *testing.T) {
	forgetHostIdentity("192.0.2.6")
	if recallHostIdentity("192.0.2.6") != "" {
		t.Fatal("fresh host must have no pin")
	}
	recordHostIdentity("192.0.2.6", "vault")
	if recallHostIdentity("192.0.2.6") != "vault" {
		t.Fatal("pin must recall")
	}
	if recallHostIdentity("192.0.2.6") != "vault" {
		t.Fatal("pin must persist")
	}
	forgetHostIdentity("192.0.2.6")
	if recallHostIdentity("192.0.2.6") != "" {
		t.Fatal("forget must clear")
	}
	_ = forgetHostIdentity
}

// Elevation matrix: elevated never relaunches; unelevated with live holder
// bows out without touching the scheduler; unelevated alone requests
// exactly one handoff; scheduler failure falls back to unelevated.
func TestEnsureElevatedMatrix(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	oldPriv, oldTask := nmsPrivElevated, nmsElevateTask
	t.Cleanup(func() { nmsPrivElevated, nmsElevateTask = oldPriv, oldTask })

	calls := 0
	nmsElevateTask = func(self, args string) error { calls++; return nil }

	nmsPrivElevated = func() bool { return true }
	if !ensureElevated() {
		t.Fatal("elevated must keep running")
	}
	if calls != 0 {
		t.Fatal("elevated must never touch the scheduler")
	}
	// Live holder present: bow out, no scheduler touch. Record OUR OWN
	// live process (guaranteed alive with matching create time).
	ours, err := ownPidRecord()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(NMSPidPath(), []byte(strconv.Itoa(ours.pid)+"\n"+strconv.FormatInt(ours.createMs, 10)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nmsPrivElevated = func() bool { return false }
	if ensureElevated() {
		t.Fatal("live holder present must bow out (return false)")
	}
	if calls != 0 {
		t.Fatal("bow-out must not touch the scheduler")
	}
	// No holder: exactly one handoff, then bow out.
	_ = os.Remove(NMSPidPath())
	if ensureElevated() {
		t.Fatal("handoff must return false (caller exits)")
	}
	if calls != 1 {
		t.Fatalf("handoff must request exactly once, got %d", calls)
	}
	// Scheduler failure: best effort, keep running unelevated.
	_ = os.Remove(NMSPidPath())
	nmsElevateTask = func(self, args string) error { calls++; return errors.New("denied") }
	if !ensureElevated() {
		t.Fatal("scheduler failure must fall back to unelevated")
	}
	if calls != 2 {
		t.Fatalf("fallback path must attempt once, got %d", calls)
	}
}

// Fallback routing: access-denied + vault creds present -> vault path end
// to end (establish, copy, cred-launch, verify, teardown, identity pin);
// missing creds -> honest terminal copy-failed, no fallback.
func TestCloneFallbackRouting(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	oldVault := nmsVaultDirOverride
	nmsVaultDirOverride = dir
	t.Cleanup(func() { nmsVaultDirOverride = oldVault })
	resetCloneState()
	nmsClearBreaker()
	oldWrite, oldExec, oldVerify, oldEst, oldDel, oldCredExec, oldTear := nmsSMBWriteFile, nmsRemoteCreate, nmsCloneVerify, smbSessionEstablish, nmsRemoteDelete, nmsRemoteCreateCred, smbSessionTeardown
	t.Cleanup(func() {
		nmsSMBWriteFile, nmsRemoteCreate, nmsCloneVerify, smbSessionEstablish, nmsRemoteDelete, nmsRemoteCreateCred, smbSessionTeardown = oldWrite, oldExec, oldVerify, oldEst, oldDel, oldCredExec, oldTear
	})
	payload := make([]byte, 10*1024*1024)
	payload[0], payload[1] = 'M', 'Z'
	if err := os.WriteFile(NMSInstallerPath(), payload, 0644); err != nil {
		t.Fatal(err)
	}
	denied := &os.PathError{Op: "open", Path: `\\h\ADMIN$`, Err: syscall.Errno(5)}
	// No cred file: access denied stays a terminal copy-failed.
	nmsSMBWriteFile = func(dest string, data []byte) error { return denied }
	if st, _ := CloneToHost("192.0.2.70", "9.9.9"); st != "copy-failed" {
		t.Fatalf("no-creds denied must terminal fail, got %q", st)
	}
	// With creds: fallback runs the vault path end to end.
	if err := os.WriteFile(NMSCredPath(), []byte("vaultuser\nvaultpass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var established, launched, verified, torn bool
	sessionLive := false
	nmsSMBWriteFile = func(dest string, data []byte) error {
		// Mirrors production: plain UNC writes fail as current context
		// but ride a live vault session.
		if sessionLive {
			return nil
		}
		return denied
	}
	nmsRemoteCreateCred = func(host, cmd string) error { launched = true; return nil }
	nmsCloneVerify = func(host, ver string, d time.Duration) bool { verified = true; return true }
	smbSessionEstablish = func(host string) error { established = true; sessionLive = true; return nil }
	smbSessionTeardown = func(host string) { torn = true }
	st, detail := CloneToHost("192.0.2.71", "9.9.9")
	if st != "cloned-verified" {
		t.Fatalf("vault path must verify, got %q (%s)", st, detail)
	}
	for name, got := range map[string]bool{"established": established, "launched": launched, "verified": verified, "torn": torn} {
		if !got {
			t.Fatalf("vault path skipped %s", name)
		}
	}
	if recallHostIdentity("192.0.2.71") != "vault" {
		t.Fatal("success must pin vault identity")
	}
	forgetHostIdentity("192.0.2.71")
}
