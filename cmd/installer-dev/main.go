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

func doUninstall() {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	installDir := filepath.Join(programFiles, "RMM", "Controller")
	fmt.Printf("Uninstalling from %s\n", installDir)
	for _, n := range []string{"controller-native.exe", "controller-ui.exe", "controller.exe"} {
		_, _ = exec.Command("taskkill", "/F", "/IM", n).CombinedOutput()
	}
	desktop := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	_ = os.Remove(filepath.Join(desktop, "Controller.lnk"))
	_ = os.Remove(filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\RMM Controller.lnk`))
	_, _ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=RMM Controller").CombinedOutput()
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RMM Controller`)
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
	target := filepath.Join(installDir, "controller-ui.exe")
	// Ensure target exists, fallback to controller.exe
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
	// Create uninstall.exe as copy of self with --uninstall flag (simple)
	uninstallPath := filepath.Join(installDir, "uninstall.exe")
	self, _ := os.Executable()
	if data, err := os.ReadFile(self); err == nil {
		_ = os.WriteFile(uninstallPath, data, 0755)
	}

	fmt.Println("[*] Install complete!")
	msgBox("RMM Controller", "Controller installed to:\n"+installDir+"\n\nDesktop shortcut created.\n\nRun Controller.lnk to start.", 0x40)
}
