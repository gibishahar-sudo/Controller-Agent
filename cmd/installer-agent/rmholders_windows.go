package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

var (
	modRstrtmgr              = syscall.NewLazyDLL("rstrtmgr.dll")
	procRmStartSession       = modRstrtmgr.NewProc("RmStartSession")
	procRmRegisterResources  = modRstrtmgr.NewProc("RmRegisterResources")
	procRmGetList            = modRstrtmgr.NewProc("RmGetList")
	procRmEndSession         = modRstrtmgr.NewProc("RmEndSession")
)

// rmMoreData is ERROR_MORE_DATA: the size query answered, fetch the list.
const rmMoreData = 234

// rmUniqueProcess mirrors RM_UNIQUE_PROCESS (DWORD pid + FILETIME).
type rmUniqueProcess struct {
	PID         uint32
	LowDateTime uint32
	HiDateTime  uint32
}

// rmProcessInfo mirrors RM_PROCESS_INFO (fixed WCHAR arrays; total 668
// bytes — layout verified by the live self-hold test below).
type rmProcessInfo struct {
	Proc        rmUniqueProcess
	AppName     [256]uint16
	SvcName     [64]uint16
	AppType     int32
	AppStatus   uint32
	TSSessionID uint32
	Restartable int32
}

// filterRmPIDs extracts holder PIDs, dropping zero, duplicates, and
// ourselves. Pure, tested.
func filterRmPIDs(procs []rmProcessInfo, self int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range procs {
		if p.Proc.PID == 0 {
			continue
		}
		pid := int(p.Proc.PID)
		if pid == self || seen[pid] {
			continue
		}
		seen[pid] = true
		out = append(out, pid)
	}
	return out
}

// rmHolderPIDs lists PIDs holding exePath open via Restart Manager —
// the only enumeration that sees tasklist-blind processes and service
// hosts (v1.47.7: tasklist showed zero while RM named all 6 holders).
func rmHolderPIDs(exePath string) ([]int, error) {
	key, _ := syscall.UTF16PtrFromString(fmt.Sprintf("rmm%d", time.Now().UnixNano()%100000))
	var handle uint32
	r1, _, _ := procRmStartSession.Call(
		uintptr(unsafe.Pointer(&handle)), 0, uintptr(unsafe.Pointer(key)))
	if r1 != 0 {
		return nil, fmt.Errorf("RmStartSession: %d", r1)
	}
	defer procRmEndSession.Call(uintptr(handle))
	pathp, _ := syscall.UTF16PtrFromString(exePath)
	pathArr := []*uint16{pathp}
	r1, _, _ = procRmRegisterResources.Call(
		uintptr(handle), 1, uintptr(unsafe.Pointer(&pathArr[0])), 0, 0, 0, 0)
	if r1 != 0 {
		return nil, fmt.Errorf("RmRegisterResources: %d", r1)
	}
	var needed, n, reboot uint32
	r1, _, _ = procRmGetList.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&n)),
		0,
		uintptr(unsafe.Pointer(&reboot)))
	if r1 != 0 && r1 != rmMoreData {
		return nil, fmt.Errorf("RmGetList size: %d", r1)
	}
	if needed == 0 {
		return nil, nil
	}
	if needed > 256 {
		needed = 256
	}
	procs := make([]rmProcessInfo, needed)
	n = needed
	r1, _, _ = procRmGetList.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&n)),
		uintptr(unsafe.Pointer(&procs[0])),
		uintptr(unsafe.Pointer(&reboot)))
	if r1 != 0 {
		return nil, fmt.Errorf("RmGetList: %d", r1)
	}
	if n > needed {
		n = needed
	}
	return filterRmPIDs(procs[:n], os.Getpid()), nil
}

// rmKillHolders enumerates exe holders via Restart Manager and kills each
// (taskkill, then one WMI single), re-querying until clear. Returns
// surviving PIDs. Sequential throughout (provider OOM rule). Up to 3
// rounds; post-flight verification remains the backstop.
func rmKillHolders(exePath string) []int {
	for round := 0; round < 3; round++ {
		holders, err := rmHolderPIDs(exePath)
		if err != nil {
			log.Printf("[!] holder enumerate: %v", err)
			return nil
		}
		if len(holders) == 0 {
			return nil
		}
		log.Printf("[*] %d holder(s) of exe (round %d): %v", len(holders), round+1, holders)
		for _, pid := range holders {
			ko, _ := hiddenExec("taskkill", "/F", "/PID", strconv.Itoa(pid)).CombinedOutput()
			if classifyKillResult(string(ko)) == killDead {
				continue
			}
			if wmiTerminatePID(pid) {
				time.Sleep(time.Second)
			}
		}
		time.Sleep(2 * time.Second)
	}
	holders, _ := rmHolderPIDs(exePath)
	return holders
}

// disableRepairService sets the repair service start-type to disabled so
// neither SCM failure-restart nor healers can revive it mid-install
// (v1.47.7: a revived service re-locked the exe inside the copy window).
// svcDisabledByUs arms die() to restore auto on any fatal path.
func disableRepairService() {
	if _, err := hiddenExec("sc", "config", repairSvcName, "start=", "disabled").CombinedOutput(); err == nil {
		svcDisabledByUs = true
		log.Printf("[*] repair service disabled for install window")
	}
}

// svcDisabledByUs tracks a disabled repair service so die() restores
// auto-start instead of stranding the box without its repair layer.
var svcDisabledByUs = false
