//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var lockFile *os.File

// ensureSingleInstance makes sure only one agent runs per PC. The first
// starter holds an exclusive file lock; a later starter kills the stale
// holder(s) and takes over. This heals the classic duplicate-agent mess
// (zombie survives upgrade → every command runs twice) automatically on
// every reinstall, reboot, or manual start.
//
// Now with PID tracking: the lock file stores our PID so we can detect
// stale locks from dead processes (crash/kill without cleanup) and auto-reclaim.
func ensureSingleInstance() {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "RMM")
	if dir == filepath.Join("", "RMM") || os.Getenv("LOCALAPPDATA") == "" {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	_ = os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "agent.lock")

	// Write our PID into the lock file so other instances can check if
	// the lock holder is still alive. If the holder is dead, we remove
	// the stale lock file and retry immediately.
	for attempt := 0; attempt < 5; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Printf("[!] singleton lock open: %v", err)
			return
		}
		if tryLock(f) {
			// We got the lock: write our PID so future instances can verify liveness.
			pid := os.Getpid()
			if _, err := f.WriteString(strconv.Itoa(pid)); err != nil {
				log.Printf("[!] singleton write pid: %v", err)
			}
			lockFile = f // held for process lifetime
			return
		}
		// Lock held by someone else: read their PID and check if process is alive.
		pidBytes := make([]byte, 16)
		n, _ := f.ReadAt(pidBytes, 0)
		f.Close()
		if n > 0 {
			if holderPid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes[:n]))); err == nil && holderPid != 0 {
				if !isProcessAlive(holderPid) {
					log.Printf("[*] stale lock from dead pid %d, removing", holderPid)
					_ = os.Remove(path)
					continue // retry immediately with clean lock file
				}
			}
		}
		// Holder is alive: kill duplicates and retry.
		killed := killOtherAgents()
		log.Printf("[*] another agent holds the lock, reaped %d stale process(es), retrying...", killed)
		time.Sleep(1500 * time.Millisecond)
	}
	log.Printf("[!] proceeding with duplicate risk: lock still held after retries")
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

// killOtherAgents terminates agent processes other than ourselves, under
// both the current and pre-rename binary names.
func killOtherAgents() int {
	self := os.Getpid()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return 0
	}
	killed := 0
	for {
		name := windows.UTF16ToString(pe.ExeFile[:])
		if (strings.EqualFold(name, "MicrosoftWindowsClient.exe") || strings.EqualFold(name, "agent.exe")) && int(pe.ProcessID) != self {
			if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pe.ProcessID); err == nil {
				if err := windows.TerminateProcess(h, 1); err == nil {
					killed++
					log.Printf("[*] reaped stale agent pid %d", pe.ProcessID)
				}
				windows.CloseHandle(h)
			}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return killed
}
