package commands

// NMS credential discovery (nms-find + autofind).
//
// The clone arm walls on hosts where the current context lacks ADMIN$ rights:
// they come back managed-unknown and get skipped forever. This file gives the
// NMS a way to DISCOVER a credential for such a host, persist it to the vault
// file (NMSCredPath, the exact two-line format the CIM/SMB fallbacks read),
// and let the existing fallback do the rest. Nothing about the clone
// pipeline changes.
//
// Shipping: Find-Credential.ps1 + Validate-Credential.ps1 live in NMSRoot
// (same pattern as Agent-Setup.exe; the installer payload walk stages them).
//
// Contract with the finder: run with -Json, parse the single
// {"user":...,"pass":...} stdout line, never scrape human output. The
// password appears ONLY in that JSON on stdout and in the vault file -
// never in logs, never on a command line, never over the controller
// channel.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Paths + presence (mirrors NMSInstallerInfo).
// ---------------------------------------------------------------------------

// NMSFinderPath is the credential finder shipped beside the agent.
func NMSFinderPath() string { return filepath.Join(NMSRoot(), "Find-Credential.ps1") }

// NMSValidatorPath is the single-credential validator the finder calls
// (kept as its own file so the operator can also run it standalone).
func NMSValidatorPath() string { return filepath.Join(NMSRoot(), "Validate-Credential.ps1") }

// NMSFinderInfo reports the finder scripts on disk (size, sha, sanity).
// Missing/undersized/non-param reads as absent: nms-find then reports
// no-finder honestly instead of shelling garbage.
func NMSFinderInfo() (size int64, sha string, ok bool) {
	b, err := os.ReadFile(NMSFinderPath())
	if err != nil || len(b) < 512 {
		return 0, "", false
	}
	if _, err := os.Stat(NMSValidatorPath()); err != nil {
		return 0, "", false
	}
	if !strings.Contains(string(b), "param(") {
		return 0, "", false
	}
	return int64(len(b)), shaBytes(b), true
}

// ---------------------------------------------------------------------------
// JSON contract + outcome classification (pure, tested).
// ---------------------------------------------------------------------------

// parseFinderJSON extracts the finder's one machine-readable contract line
// from captured output. Chatter-tolerant: scans lines, accepts the first
// that unmarshals with both keys present. A blank PASSWORD is a legal hit
// (Windows default Administrator can be blank); a blank USER is not.
func parseFinderJSON(out []byte) (user, pass string, ok bool) {
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, `{"user":`) || !strings.Contains(ln, `"pass"`) {
			continue
		}
		var r struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if json.Unmarshal([]byte(ln), &r) == nil && strings.TrimSpace(r.User) != "" {
			return r.User, r.Pass, true
		}
	}
	return "", "", false
}

// finderOutcome classifies a finder run into exactly one of: found (with
// the validated pair), timeout, no-hit. Never a hang, never ambiguous.
func finderOutcome(out []byte, err error) (user, pass, state string) {
	if u, p, ok := parseFinderJSON(out); ok {
		return u, p, "found"
	}
	if err != nil && strings.Contains(err.Error(), "timed out") {
		return "", "", "timeout"
	}
	return "", "", "no-hit"
}

// ---------------------------------------------------------------------------
// Runner + vault persistence.
// ---------------------------------------------------------------------------

// findDefaultTimeout bounds one finder run. A 400-candidate pass with
// per-attempt WMI no-ops runs minutes, not hours; a slow target doubles
// it, so the default sits at 15 minutes (a working find must never
// misclassify as timeout). The timeout is the hard backstop, and a
// timeout is classified, never a hang.
const findDefaultTimeout = 15 * time.Minute

// nmsFindRun executes the finder against one host under a hard timeout and
// classifies the outcome. Var so tests cut the powershell hop.
var nmsFindRun = func(host string, timeout time.Duration, hints []string) (user, pass, state string) {
	args := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", NMSFinderPath(), "-Target", host}
	if len(hints) > 0 {
		args = append(args, "-Hints", strings.Join(hints, ","))
	}
	args = append(args, "-Json")
	out, err := runWithTimeout(timeout, "powershell", args...)
	return finderOutcome(out, err)
}

// writeVaultCred persists the two-line vault credential (user, pass) that
// the CIM/SMB fallbacks read. Atomic temp+rename, 0600 (the vault dir is
// SYSTEM+Administrators; the file itself stays tight anyway). The password
// is never logged and never returned over the controller channel.
//
// NOTE: the vault cred is GLOBAL - a pair found for one host becomes the
// pair for every host (one file, no per-host slots). Correct on a flat
// workgroup LAN (same admin everywhere); on a heterogeneous LAN the first
// different box reads no-hit against the shared pair. That is the design,
// not a bug.
func writeVaultCred(user, pass string) error {
	data := []byte(user + "\n" + pass + "\n")
	tmp := NMSCredPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, NMSCredPath())
}

// ---------------------------------------------------------------------------
// Find job ledger (same machinery as startCloneJob: per-host entry, in-flight
// dedupe, cooldown, honest terminal states, breaker participation).
// ---------------------------------------------------------------------------

// findHostCooldown suppresses relaunches after a terminal find state: the
// finder is expensive (hundreds of bounded attempts), so a no-hit box stays
// quiet for an hour instead of being re-hunted every interval.
const findHostCooldown = 60 * time.Minute

type findJob struct {
	State  string // finding | found | no-hit | timeout | no-finder | find-failed
	Detail string
	At     time.Time
	Done   bool
	Forced bool
}

var findMu sync.Mutex
var findJobs = map[string]*findJob{}

// findEvent pushes onto the shared (clone) event bus; events surface in
// the next NMS report (start / found / failed).
func findEvent(s string) {
	cloneMu.Lock()
	pushCloneEvent(s)
	cloneMu.Unlock()
}

// startFindJob launches one tracked find unless a job is already in flight
// or a terminal state is still cooling down. The job runs in its own
// goroutine - a find NEVER blocks a monitor cycle. On success it writes
// the vault cred and pushes an event; the NEXT cycle's clone attempt picks
// it up (no inline cloning from inside the find job). Find failures count
// toward the same breaker budget as the clone arm; a found pair decays it.
func startFindJob(host string, timeout time.Duration, forced bool) (state string, started bool) {
	now := time.Now()
	if _, _, ok := NMSFinderInfo(); !ok {
		return "no-finder", false
	}
	findMu.Lock()
	if j, ok := findJobs[host]; ok {
		if !j.Done {
			findMu.Unlock()
			return "finding", false
		}
		if now.Sub(j.At) < findHostCooldown {
			st := j.State
			findMu.Unlock()
			return "find-cooldown-" + st, false
		}
	}
	findJobs[host] = &findJob{State: "finding", Detail: "job started", At: now, Forced: forced}
	// Opportunistic prune (same as the clone ledger).
	for h, j := range findJobs {
		if j.Done && now.Sub(j.At) > 2*findHostCooldown {
			delete(findJobs, h)
		}
	}
	findMu.Unlock()
	go func() {
		user, pass, st := nmsFindRun(host, timeout, LoadNMSConfig().FindHints)
		detail := ""
		switch st {
		case "found":
			if err := writeVaultCred(user, pass); err != nil {
				st, detail = "find-failed", "vault write: "+strings.TrimSpace(err.Error())
				nmsRecordFail()
			} else {
				detail = "vault cred written - next clone cycle picks it up"
				nmsRecordSuccess()
			}
		case "timeout":
			detail = "finder timed out (bounded and classified)"
			nmsRecordFail()
		default: // no-hit
			detail = "no candidate validated"
			nmsRecordFail()
		}
		findMu.Lock()
		findJobs[host] = &findJob{State: st, Detail: detail, At: time.Now(), Done: true, Forced: forced}
		findMu.Unlock()
		evt := "find " + host + ": " + st + " - " + detail
		if forced {
			evt = "operator: " + evt
		}
		findEvent(evt)
	}()
	return "finding", true
}

// findJobLookup returns the tracked find state+detail for a host, if any.
func findJobLookup(host string) (state, detail string, tracked bool) {
	findMu.Lock()
	defer findMu.Unlock()
	j, ok := findJobs[host]
	if !ok {
		return "", "", false
	}
	return j.State, j.Detail, true
}

// maybeAutoFind is the clone-arm hook: when autofind is enabled, a host was
// skipped as managed-unknown, the vault cred file is absent, and no find job
// is tracked for it, start one BACKGROUND find job. Gates (self,
// controller, excluded) are re-checked here so the hook can never fire for
// a box the clone arm itself would refuse. Bookkeeping only - no LAN I/O.
func maybeAutoFind(cfg NMSConfig, host string, controllerIPs []string) (state string, started bool) {
	if !cfg.AutoFind {
		return "", false
	}
	if vaultCredsPresent() {
		return "", false
	}
	if _, _, ok := NMSFinderInfo(); !ok {
		return "", false
	}
	if elig, _ := CloneEligible(host, true, false, cfg.Exclude, selfIPs(), controllerIPs); !elig {
		return "", false
	}
	return startFindJob(host, findDefaultTimeout, false)
}

// ---------------------------------------------------------------------------
// nms-find verb.
// ---------------------------------------------------------------------------

// nmsFindVerb implements `nms-find <host> [--timeout Sec] [--write]`.
//
// Gates are the clone/exec set (reachable, not self, not controller, not
// excluded) with ONE deliberate difference: the managed veto is SKIPPED - a
// managed box can still be the one whose credential we lack, and finding it
// is exactly the point. Runs the finder under a hard timeout, parses the
// JSON contract, prints the pair (password masked in the reply - it lives
// only in the vault file), and with --write persists it to NMSCredPath.
func nmsFindVerb(args string, controllerIPs []string) (string, error) {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "", fmt.Errorf("usage: nms-find <host> [--timeout Sec] [--write] (managed boxes allowed: the credential we lack may be theirs)")
	}
	host := parts[0]
	timeout := findDefaultTimeout
	write := false
	for i := 1; i < len(parts); i++ {
		switch {
		case strings.EqualFold(parts[i], "--write"):
			write = true
		case parts[i] == "--timeout" && i+1 < len(parts):
			n, err := strconv.Atoi(parts[i+1])
			if err != nil || n < 60 || n > 1800 {
				return "", fmt.Errorf("--timeout must be 60..1800 (seconds)")
			}
			timeout = time.Duration(n) * time.Second
			i++
		default:
			return "", fmt.Errorf("unknown nms-find flag %q (usage: nms-find <host> [--timeout Sec] [--write])", parts[i])
		}
	}
	if !TCPReachable(host) {
		return "", fmt.Errorf("find refused: %s unreachable (no 445/135/139/3389)", host)
	}
	if _, _, ok := NMSFinderInfo(); !ok {
		return "", fmt.Errorf("find refused: finder scripts missing beside the agent (%s) - update to ship them", NMSFinderPath())
	}
	cfg := LoadNMSConfig()
	// Managed veto deliberately skipped (unlike clone/exec): a managed box
	// can still be the one whose credential we lack.
	if elig, reason := CloneEligible(host, true, false, cfg.Exclude, selfIPs(), controllerIPs); !elig {
		return "", fmt.Errorf("find refused: %s", reason)
	}
	user, pass, st := nmsFindRun(host, timeout, cfg.FindHints)
	switch st {
	case "found":
		masked := fmt.Sprintf("pass=****(%d chars)", len(pass))
		if write {
			if err := writeVaultCred(user, pass); err != nil {
				return "", fmt.Errorf("find %s: found but vault write failed: %v", host, err)
			}
			return fmt.Sprintf("find %s: found user=%s %s - vault cred written (%s); the next clone attempt uses it", host, user, masked, NMSCredPath()), nil
		}
		return fmt.Sprintf("find %s: found user=%s %s - retry with --write to persist to the vault", host, user, masked), nil
	case "timeout":
		return "", fmt.Errorf("find %s: timed out after %s (bounded and classified - raise --timeout or re-run)", host, timeout)
	default:
		return "", fmt.Errorf("find %s: no candidate validated (finder log: ~\\.rmm-guess)", host)
	}
}
