//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

var lockFile *os.File

// agentRole classifies a process command line into agent roles. Only
// "full" processes own the box; every other role (watcher, service,
// healer, test) coexists and must never be reaped as a "duplicate".
// Tokens match exactly (both - and -- forms); substrings never count.
func agentRole(cmdline string) string {
	for _, tok := range strings.Fields(cmdline) {
		switch strings.ToLower(strings.TrimLeft(tok, "-")) {
		case "watch":
			return "watch"
		case "svc-heal":
			return "svc"
		case "wmi-heal":
			return "wmi"
		case "test":
			return "test"
		case "persist":
			return "persist"
		}
	}
	return "full"
}

// fullAgentProcs lists PIDs that are verifiably full agents, excluding
// ourselves. Fail-closed: processes whose command line can't be read
// (SYSTEM service, other users' processes) are never touched.
func fullAgentProcs() []int32 {
	var out []int32
	self := int32(os.Getpid())
	pids, err := process.Pids()
	if err != nil {
		return nil
	}
	for _, pid := range pids {
		if pid == self {
			continue
		}
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		n := strings.ToLower(name)
		if n != "microsoftwindowsclient.exe" && n != "agent.exe" {
			continue
		}
		cl, err := p.Cmdline()
		if err != nil || cl == "" {
			continue // fail-closed: unidentified processes are never reaped
		}
		if agentRole(cl) != "full" {
			continue
		}
		out = append(out, pid)
	}
	return out
}

// procStartAge returns how long ago a PID started; ok=false when unknown.
func procStartAge(pid int) (time.Duration, bool) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, false
	}
	ms, err := p.CreateTime()
	if err != nil || ms <= 0 {
		return 0, false
	}
	return time.Since(time.UnixMilli(ms)), true
}

// terminateProc best-effort kills one PID (fails on rights, which is fine:
// a process we can't kill is one we must yield to, never duplicate).
func terminateProc(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1) == nil
}

// openLockFile opens agent.lock in the first writable candidate dir.
// The install dir comes first so the lock is per-PC (shared by every
// user/service context); per-profile dirs are fallbacks. A per-user lock
// was the old hole: SYSTEM and Admin each held their own and both ran.
func openLockFile() (*os.File, string) {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		dirs = append(dirs, filepath.Join(la, "RMM"))
	}
	dirs = append(dirs, filepath.Join(os.TempDir(), "RMM"))
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			continue
		}
		if f, err := os.OpenFile(filepath.Join(d, "agent.lock"), os.O_CREATE|os.O_RDWR, 0644); err == nil {
			return f, d
		}
	}
	return nil, ""
}

// ensureSingleInstance makes sure only one full agent runs per PC:
// exactly one agent process plus its supervisor, never two agents.
//
// Policy:
//  1. Reap verified full-agent duplicates older than 60s (upgrade
//     zombies, legacy-lock strays). Fresh starters are left alone to
//     serialize via the lock — no logon-race kill churn. Fail-closed on
//     unreadable command lines and on rights failures.
//  2. Take the common lock. If a live holder owns it and started recently,
//     wait for it to settle, then yield quietly (exit 0) — the running
//     holder already owns the box. Only an old/wedged holder is reaped,
//     and only when we have rights to do so.
func ensureSingleInstance() {
	for _, pid := range fullAgentProcs() {
		age, ok := procStartAge(int(pid))
		if !ok || age < 60*time.Second {
			continue
		}
		if terminateProc(int(pid)) {
			log.Printf("[*] reaped duplicate agent pid %d (age %s)", pid, age.Round(time.Second))
		}
	}
	for attempt := 0; attempt < 12; attempt++ {
		f, dir := openLockFile()
		if f == nil {
			log.Printf("[!] singleton: no writable lock dir, proceeding without lock")
			return
		}
		path := filepath.Join(dir, "agent.lock")
		if tryLock(f) {
			if _, err := f.WriteString(strconv.Itoa(os.Getpid())); err != nil {
				log.Printf("[!] singleton write pid: %v", err)
			}
			lockFile = f // held for process lifetime
			return
		}
		// Locked: identify the holder.
		pidBytes := make([]byte, 16)
		n, _ := f.ReadAt(pidBytes, 0)
		f.Close()
		holder := 0
		if n > 0 {
			holder, _ = strconv.Atoi(strings.TrimSpace(string(pidBytes[:n])))
		}
		if holder == 0 || holder == os.Getpid() {
			time.Sleep(2 * time.Second)
			continue
		}
		if !isProcessAlive(holder) {
			log.Printf("[*] stale lock from dead pid %d, removing", holder)
			_ = os.Remove(path)
			continue
		}
		age, ok := procStartAge(holder)
		if !ok || age >= 120*time.Second {
			// Old or wedged holder: attempt takeover, yield on rights failure.
			if terminateProc(holder) {
				log.Printf("[*] reaped stale lock holder pid %d, retrying...", holder)
				time.Sleep(1500 * time.Millisecond)
				continue
			}
			log.Printf("[*] agent pid %d owns this PC; yielding", holder)
			os.Exit(0)
		}
		// Young holder: still starting up — wait for it to settle, then
		// yield rather than duplicate. Never kill a starting peer.
		time.Sleep(5 * time.Second)
	}
	log.Printf("[*] lock never freed; yielding to the running agent")
	os.Exit(0)
}

// isProcessAlive checks if a Windows process with the given PID exists.
func isProcessAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	err = windows.GetExitCodeProcess(h, &code)
	if err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func tryLock(f *os.File) bool {
	var ol windows.Overlapped
	// LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY: don't block.
	err := windows.LockFileEx(windows.Handle(f.Fd()), 0x00000002|0x00000001, 0, 1, 0, &ol)
	return err == nil
}
