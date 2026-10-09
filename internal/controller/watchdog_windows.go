//go:build windows

package controller

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ensureWatchdogLauncher migrates existing controller-watchdog persistence
// to the flash-free wscript launcher (v1.46.96): powershell.exe spawned
// from Run keys and scheduled tasks allocates a console that visibly
// flashes on every logon, unlock, and 15-minute repetition; wscript
// never does. Idempotent; boxes without a controller install (no Run
// value) are untouched. Best effort (HKLM/task writes need admin;
// failures log and move on — the installer path is authoritative).
func ensureWatchdogLauncher() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	cur, _, err := k.GetStringValue("WindowsUpdateController")
	if err != nil || cur == "" {
		return
	}
	ps1 := ps1FromRun(cur)
	if ps1 == "" {
		return
	}
	vbs := strings.TrimSuffix(ps1, ".ps1") + ".vbs"
	if b, err := os.ReadFile(vbs); err != nil || string(b) != watchVbsText {
		if err := os.WriteFile(vbs, []byte(watchVbsText), 0644); err != nil {
			log.Printf("[watchdog] launcher write failed: %v", err)
			return
		}
	}
	if want := watchRunValue(vbs); cur != want {
		if err := k.SetStringValue("WindowsUpdateController", want); err != nil {
			log.Printf("[watchdog] Run migrate failed: %v", err)
			return
		}
		log.Printf("[watchdog] Run value migrated to flash-free launcher")
	}
	// Task action: export, edit, recreate (schtasks /change /tr mangles
	// quoted spaced paths, so it can't do this job).
	out, err := exec.Command("schtasks", "/query", "/tn", "WindowsUpdateController", "/xml").CombinedOutput()
	if err != nil {
		return // no task: installer owns creation, not us
	}
	migrated, changed := migrateTaskXML(string(out), vbs)
	if !changed {
		return
	}
	tmp := filepath.Join(os.TempDir(), "rmm_watchdog_task.xml")
	if err := os.WriteFile(tmp, []byte(migrated), 0644); err != nil {
		log.Printf("[watchdog] task xml stage failed: %v", err)
		return
	}
	defer os.Remove(tmp)
	if _, err := exec.Command("schtasks", "/delete", "/tn", "WindowsUpdateController", "/f").CombinedOutput(); err != nil {
		log.Printf("[watchdog] task delete failed: %v", err)
		return
	}
	if out2, err := exec.Command("schtasks", "/create", "/tn", "WindowsUpdateController", "/xml", tmp).CombinedOutput(); err != nil {
		log.Printf("[watchdog] task recreate failed: %v %s", err, strings.TrimSpace(string(out2)))
		return
	}
	log.Printf("[watchdog] task migrated to flash-free launcher")
}
