//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
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
func ensureSingleInstance() {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "RMM")
	if dir == filepath.Join("", "RMM") || os.Getenv("LOCALAPPDATA") == "" {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	_ = os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "agent.lock")
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			log.Printf("[!] singleton lock open: %v", err)
			return
		}
		if tryLock(f) {
			lockFile = f // held for process lifetime
			return
		}
		f.Close()
		killed := killOtherAgents()
		log.Printf("[*] another agent holds the lock, reaped %d stale process(es), retrying...", killed)
		time.Sleep(1500 * time.Millisecond)
	}
	log.Printf("[!] proceeding with duplicate risk: lock still held")
}

func tryLock(f *os.File) bool {
	var ol windows.Overlapped
	// LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY: don't block.
	err := windows.LockFileEx(windows.Handle(f.Fd()), 0x00000002|0x00000001, 0, 1, 0, &ol)
	return err == nil
}

// killOtherAgents terminates agent.exe processes other than ourselves.
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
		if strings.EqualFold(name, "agent.exe") && int(pe.ProcessID) != self {
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
