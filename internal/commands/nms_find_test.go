package commands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetFindState clears the find ledger (test isolation).
func resetFindState() {
	findMu.Lock()
	findJobs = map[string]*findJob{}
	findMu.Unlock()
}

// stageFinderScripts writes minimal finder+validator scripts into a test
// NMSRoot so NMSFinderInfo reads present.
func stageFinderScripts(t *testing.T) {
	t.Helper()
	body := strings.Repeat("# finder stub\n", 40) + "param($Target)\n"
	if err := os.WriteFile(NMSFinderPath(), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(NMSValidatorPath(), []byte("# validator stub\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

// withVaultDir points the vault (cred file) at a temp dir.
func withVaultDir(t *testing.T) {
	t.Helper()
	old := nmsVaultDirOverride
	nmsVaultDirOverride = t.TempDir()
	t.Cleanup(func() { nmsVaultDirOverride = old })
}

// withFindRun replaces the powershell hop with a fake.
func withFindRun(t *testing.T, fn func(host string, timeout time.Duration, hints []string) (string, string, string)) {
	t.Helper()
	old := nmsFindRun
	nmsFindRun = fn
	t.Cleanup(func() { nmsFindRun = old })
}

// --- JSON contract ---

func TestParseFinderJSON(t *testing.T) {
	// Contract line amid Write-Host chatter (stream capture mixes them).
	chatter := "STAGE: auth OK\r\n[1/76] tier=t0-derived user=Administrator pass=****\r\n" +
		`{"user":"PC\\Administrator","pass":"s3cret!"}` + "\r\nRESULT: PASS\n"
	u, p, ok := parseFinderJSON([]byte(chatter))
	if !ok || u != `PC\Administrator` || p != "s3cret!" {
		t.Fatalf("chatter parse failed: ok=%v u=%q p=%q", ok, u, p)
	}
	// Blank password is a legal hit; blank user is not.
	u, p, ok = parseFinderJSON([]byte(`{"user":"Administrator","pass":""}`))
	if !ok || u != "Administrator" || p != "" {
		t.Fatalf("blank pass must be a hit: ok=%v u=%q p=%q", ok, u, p)
	}
	if _, _, ok = parseFinderJSON([]byte(`{"user":"x"}`)); ok {
		t.Fatal("missing pass key must not parse as a hit")
	}
	if _, _, ok = parseFinderJSON([]byte("no json here at all")); ok {
		t.Fatal("no JSON must not parse")
	}
	// Trailing junk after the object is tolerated (CRLF, spaces).
	if _, _, ok = parseFinderJSON([]byte(`  {"user":"u1","pass":"p1"}  `)); !ok {
		t.Fatal("padded contract line must parse")
	}
}

func TestFinderOutcome(t *testing.T) {
	if u, _, st := finderOutcome([]byte(`{"user":"a","pass":"b"}`), nil); st != "found" || u != "a" {
		t.Fatalf("want found, got %q", st)
	}
	if _, _, st := finderOutcome(nil, errors.New("timed out after 10m0s")); st != "timeout" {
		t.Fatalf("want timeout, got %q", st)
	}
	if _, _, st := finderOutcome([]byte("RESULT: no candidate passed"), nil); st != "no-hit" {
		t.Fatalf("want no-hit, got %q", st)
	}
	// A timeout WITH a valid line still wins: the line proves the finder
	// finished and validated before the process was reaped.
	if _, _, st := finderOutcome([]byte(`{"user":"a","pass":"b"}`), errors.New("timed out after 10m0s")); st != "found" {
		t.Fatalf("late line must classify found, got %q", st)
	}
}

// --- vault persistence ---

func TestWriteVaultCred(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	withVaultDir(t)
	if err := writeVaultCred("Administrator", "p@ss"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(NMSCredPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "Administrator\np@ss\n" {
		t.Fatalf("vault format wrong: %q", string(b))
	}
	// The exact shape the fallbacks read: two non-empty lines.
	if !vaultCredsPresent() {
		t.Fatal("written cred must satisfy vaultCredsPresent")
	}
}

// --- nms-find verb gate matrix ---

func TestNMSFindVerbGates(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stageFinderScripts(t)
	withVaultDir(t)
	resetFindState()

	oldDial := dialTCP
	dialTCP = func(string, int, time.Duration) bool { return true }
	t.Cleanup(func() { dialTCP = oldDial })

	// Seed excluded list via config.
	cfg := LoadNMSConfig()
	cfg.Exclude = []string{"10.8.8.8"}
	if err := SaveNMSConfig(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(NMSConfigPath()) })

	cases := []struct {
		name, host, wantIn string
		wantErr            bool
	}{
		{"unreachable", "10.1.1.1", "unreachable", true},
		{"excluded", "10.8.8.8", "excluded", true},
		{"controller", "10.9.9.9", "controller", true},
	}
	// Unreachable needs dial=false for that host only.
	dialTCP = func(host string, _ int, _ time.Duration) bool { return host != "10.1.1.1" }
	for _, c := range cases {
		if c.name == "controller" {
			_, err := NMSHandle("nms-find", c.host, []string{"10.9.9.9"})
			if err == nil || !strings.Contains(err.Error(), c.wantIn) {
				t.Fatalf("%s: want err %q, got %v", c.name, c.wantIn, err)
			}
			continue
		}
		_, err := NMSHandle("nms-find", c.host, nil)
		if (err == nil) == c.wantErr || (c.wantErr && err != nil && !strings.Contains(err.Error(), c.wantIn)) {
			t.Fatalf("%s: want err containing %q, got %v", c.name, c.wantIn, err)
		}
	}
	// Self: the verb must refuse own-box addresses.
	if ips := selfIPs(); len(ips) > 0 {
		if _, err := NMSHandle("nms-find", ips[0], nil); err == nil || !strings.Contains(err.Error(), "self") {
			t.Fatalf("self must be refused, got %v", err)
		}
	}
	// Missing scripts read as no-finder.
	if err := os.Remove(NMSValidatorPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := NMSHandle("nms-find", "10.2.2.2", nil); err == nil || !strings.Contains(err.Error(), "no-finder") {
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "finder scripts missing") {
			t.Fatalf("missing finder must refuse, got %v", err)
		}
	}
}

// The managed veto is deliberately SKIPPED for nms-find: a managed box can
// still be the one whose credential we lack.
func TestNMSFindVerbManagedAllowed(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stageFinderScripts(t)
	withVaultDir(t)
	resetFindState()

	oldDial := dialTCP
	dialTCP = func(string, int, time.Duration) bool { return true }
	t.Cleanup(func() { dialTCP = oldDial })

	// Host reads as managed-unknown (share read denied).
	oldRead := nmsReadUNC
	nmsReadUNC = func(p string) ([]byte, error) {
		return nil, os.ErrPermission
	}
	t.Cleanup(func() { nmsReadUNC = oldRead })

	withFindRun(t, func(string, time.Duration, []string) (string, string, string) {
		return "Administrator", "pw", "found"
	})
	res, err := NMSHandle("nms-find", "10.3.3.3", nil)
	if err != nil {
		t.Fatalf("managed host must be findable, got %v", err)
	}
	if !strings.Contains(res, "Administrator") || strings.Contains(res, "pw") {
		t.Fatalf("reply must carry user but never the password, got %q", res)
	}
}

// --write persists the pair to the vault in the two-line format.
func TestNMSFindVerbWrite(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stageFinderScripts(t)
	withVaultDir(t)
	resetFindState()

	oldDial := dialTCP
	dialTCP = func(string, int, time.Duration) bool { return true }
	t.Cleanup(func() { dialTCP = oldDial })

	withFindRun(t, func(string, time.Duration, []string) (string, string, string) {
		return "Administrator", "hunter2", "found"
	})
	res, err := NMSHandle("nms-find", "10.4.4.4 --write", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res, "hunter2") {
		t.Fatalf("password must never appear in the reply, got %q", res)
	}
	b, err := os.ReadFile(NMSCredPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "Administrator\nhunter2\n" {
		t.Fatalf("vault must hold the exact two lines, got %q", string(b))
	}
}

// A timed-out find classifies instead of hanging; the verb surfaces it.
func TestNMSFindVerbTimeout(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stageFinderScripts(t)
	withVaultDir(t)
	resetFindState()

	oldDial := dialTCP
	dialTCP = func(string, int, time.Duration) bool { return true }
	t.Cleanup(func() { dialTCP = oldDial })

	withFindRun(t, func(string, time.Duration, []string) (string, string, string) {
		return "", "", "timeout"
	})
	_, err := NMSHandle("nms-find", "10.5.5.5", nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout must be classified as an error, got %v", err)
	}
}

// --- find job ledger ---

func TestStartFindJobDedupeAndCooldown(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stageFinderScripts(t)
	withVaultDir(t)
	resetFindState()
	resetCloneState()

	block := make(chan struct{})
	released := make(chan struct{})
	calls := 0
	withFindRun(t, func(string, time.Duration, []string) (string, string, string) {
		calls++
		<-block
		close(released)
		return "", "", "no-hit"
	})

	if st, started := startFindJob("10.6.6.6", time.Minute, false); !started || st != "finding" {
		t.Fatalf("first start failed: st=%q started=%v", st, started)
	}
	// In-flight dedupe: second start for same host must not run twice.
	if st, started := startFindJob("10.6.6.6", time.Minute, false); started || st != "finding" {
		t.Fatalf("in-flight dedupe failed: st=%q started=%v", st, started)
	}
	close(block)
	<-released
	// Wait for the terminal state.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _, ok := findJobLookup("10.6.6.6"); ok && st == "no-hit" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st, _, ok := findJobLookup("10.6.6.6"); !ok || st != "no-hit" {
		t.Fatalf("terminal no-hit expected, got %q", st)
	}
	if calls != 1 {
		t.Fatalf("finder must run exactly once, got %d", calls)
	}
	// Cooldown: terminal state suppresses relaunch.
	if st, started := startFindJob("10.6.6.6", time.Minute, false); started || st != "find-cooldown-no-hit" {
		t.Fatalf("cooldown failed: st=%q started=%v", st, started)
	}
}

// On found, the job writes the vault cred (next cycle clones from it).
func TestStartFindJobFoundWritesVault(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stageFinderScripts(t)
	withVaultDir(t)
	resetFindState()
	resetCloneState()

	done := make(chan struct{})
	withFindRun(t, func(string, time.Duration, []string) (string, string, string) {
		return "Administrator", "found-pw", "found"
	})
	if _, started := startFindJob("10.7.7.7", time.Minute, false); !started {
		t.Fatal("job must start")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _, ok := findJobLookup("10.7.7.7"); ok && st == "found" {
			close(done)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-done:
	default:
		t.Fatal("find job never reached found")
	}
	b, err := os.ReadFile(NMSCredPath())
	if err != nil || string(b) != "Administrator\nfound-pw\n" {
		t.Fatalf("vault must hold the found pair, got %q err=%v", string(b), err)
	}
}

// --- autofind gating (maybeAutoFind) ---

func TestMaybeAutoFindMatrix(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	stageFinderScripts(t)
	withVaultDir(t)
	resetFindState()
	resetCloneState()

	ran := 0
	withFindRun(t, func(string, time.Duration, []string) (string, string, string) {
		ran++
		return "", "", "no-hit"
	})
	// Drain any job started in this test.
	drain := func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			findMu.Lock()
			busy := false
			for _, j := range findJobs {
				if !j.Done {
					busy = true
				}
			}
			findMu.Unlock()
			if !busy {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	base := NMSConfig{AutoFind: true, Exclude: []string{"10.8.8.8"}}

	// Off by default (the config default, not just an unset field).
	if _, started := maybeAutoFind(NMSConfig{Exclude: []string{"10.8.8.8"}}, "10.7.7.1", nil); started {
		t.Fatal("autofind must default to off")
	}
	// Vault cred present: no hunt needed.
	withVaultCred := t.TempDir()
	oldVault := nmsVaultDirOverride
	nmsVaultDirOverride = withVaultCred
	if err := writeVaultCred("u", "p"); err != nil {
		t.Fatal(err)
	}
	if _, started := maybeAutoFind(base, "10.7.7.1", nil); started {
		t.Fatal("existing vault cred must suppress the hunt")
	}
	nmsVaultDirOverride = oldVault

	// Controller/excluded/self never hunt.
	if _, started := maybeAutoFind(base, "10.9.9.9", []string{"10.9.9.9"}); started {
		t.Fatal("controller must not hunt")
	}
	if _, started := maybeAutoFind(base, "10.8.8.8", nil); started {
		t.Fatal("excluded must not hunt")
	}
	if ips := selfIPs(); len(ips) > 0 {
		if _, started := maybeAutoFind(base, ips[0], nil); started {
			t.Fatal("self must not hunt")
		}
	}
	// Fires exactly once per host: second call while in flight is a no-op.
	if _, started := maybeAutoFind(base, "10.7.7.2", nil); !started {
		t.Fatal("eligible host must start a hunt")
	}
	if _, started := maybeAutoFind(base, "10.7.7.2", nil); started {
		t.Fatal("second call must dedupe to not-started")
	}
	drain()
	if ran == 0 {
		t.Fatal("the fake finder must have run")
	}
}

// The clone arm skip path mentions the autofind job when it fires
// (config autofind=on, no vault cred, host managed-unknown).
func TestAutofindSetNmsKey(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	t.Cleanup(func() { _ = os.Remove(NMSConfigPath()) })
	if _, err := SetNMS("autofind=on", nil); err != nil {
		t.Fatal(err)
	}
	if !LoadNMSConfig().AutoFind {
		t.Fatal("set-nms autofind=on must persist")
	}
	if _, err := SetNMS("autofind=off", nil); err != nil {
		t.Fatal(err)
	}
	if LoadNMSConfig().AutoFind {
		t.Fatal("set-nms autofind=off must persist")
	}
	// Comma-separated list values in one field (the comma->space rewrite
	// is gone: list keys take their commas to splitList intact).
	if _, err := SetNMS("find_hints=shahar,test", nil); err != nil {
		t.Fatal(err)
	}
	got := LoadNMSConfig().FindHints
	if len(got) != 2 || got[0] != "shahar" || got[1] != "test" {
		t.Fatalf("find_hints must persist both values, got %v", got)
	}
	// Off by default on a fresh root.
	if err := os.Remove(NMSConfigPath()); err != nil {
		t.Fatal(err)
	}
	if LoadNMSConfig().AutoFind {
		t.Fatal("autofind must default off")
	}
}

// nms-status surfaces autofind state and tracked find jobs.
func TestNMSStatusShowsFindJobs(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	withVaultDir(t)
	resetFindState()
	t.Cleanup(resetFindState)

	if !strings.Contains(nmsStatus(), "autofind=off") {
		t.Fatal("status must show autofind state")
	}
	findMu.Lock()
	findJobs["10.0.0.1"] = &findJob{State: "finding", Detail: "job started", At: time.Now()}
	findMu.Unlock()
	s := nmsStatus()
	if !strings.Contains(s, "find-jobs=1(10.0.0.1:finding)") {
		t.Fatalf("status must list tracked find jobs, got %q", s)
	}
}

// Guard: payload staging includes the finder scripts (file name contract
// with the installer payload walk).
func TestFinderScriptsInPayload(t *testing.T) {
	for _, n := range []string{"Find-Credential.ps1", "Validate-Credential.ps1"} {
		if _, err := os.Stat(filepath.Join("..", "..", "cmd", "installer-agent", "payload", n)); err != nil {
			t.Fatalf("finder script %s must ship in the installer payload: %v", n, err)
		}
	}
}
