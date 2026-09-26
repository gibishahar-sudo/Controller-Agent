package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Remote notify + speech + session truth + log pull. All Windows paths use
// built-in PowerShell/.NET only (no new dependencies).

// sendNotification shows a topmost window on the REMOTE pc:
// send-notification <seconds|sticky> <text>. Fired async, returns at once —
// but only AFTER proving OUR dialog actually appeared (visible window
// owned by our child pid, up to 20s: cold PowerShell + AMSI + .NET JIT
// routinely exceed 5s). A session-0/non-interactive agent used to report
// "shown" while nobody could ever see it; now that errors instead.
func sendNotification(arg string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	parts := strings.SplitN(strings.TrimSpace(arg), " ", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("usage: send-notification <seconds|sticky> <text>")
	}
	durStr, text := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	sticky := strings.EqualFold(durStr, "sticky")
	secs, err := strconv.Atoi(durStr)
	if !sticky && (err != nil || secs <= 0 || secs > 86400) {
		return "", fmt.Errorf("usage: send-notification <seconds 1-86400|sticky> <text>")
	}
	ms := secs * 1000
	if sticky {
		ms = 0
	}
	script := notifyScript(text, ms)
	cmd := hideWindow(exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", script))
	// Death-rattle capture: if the dialog dies instantly (Add-Type bomb,
	// policy block) its stderr lands here and goes back in the error.
	// Empty file + live process + no window = wrong desktop/session.
	dbgDir := filepath.Join(os.TempDir(), "RMM")
	_ = os.MkdirAll(dbgDir, 0755)
	dbgPath := filepath.Join(dbgDir, fmt.Sprintf("notify-%d.log", time.Now().UnixNano()))
	dbg, _ := os.Create(dbgPath)
	if dbg != nil {
		cmd.Stdout = dbg
		cmd.Stderr = dbg
	}
	if err := cmd.Start(); err != nil {
		if dbg != nil {
			_ = dbg.Close()
			_ = os.Remove(dbgPath)
		}
		return "", err
	}
	if dbg != nil {
		defer func() {
			_ = dbg.Close()
			_ = os.Remove(dbgPath)
		}()
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var exitErr error
	exited := false
	// Proof, not faith: OUR dialog must become visible within 20s.
	// (Title-only matching could pass on a stale dialog; pid ownership
	// cannot. 20s, not 5s: cold PowerShell routinely needs it.)
	pid := uint32(0)
	if cmd.Process != nil {
		pid = uint32(cmd.Process.Pid)
	}
	t0 := time.Now()
	for i := 0; i < 200; i++ {
		select {
		case err := <-waitCh:
			exited = true
			exitErr = err
		default:
		}
		time.Sleep(100 * time.Millisecond)
		if pid != 0 && findVisibleWindowOwned(pid, "RMM Controller") {
			if sticky {
				return "notification shown (sticky, dismiss manually)", nil
			}
			return fmt.Sprintf("notification shown (%ds)", secs), nil
		}
	}
	tail := ""
	if b, err := os.ReadFile(dbgPath); err == nil {
		tail = strings.TrimSpace(string(b))
		if len(tail) > 500 {
			tail = tail[len(tail)-500:]
		}
	}
	if !exited && cmd.Process != nil {
		_ = hideWindow(exec.Command("taskkill", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))).Run()
	}
	secs10 := time.Since(t0).Seconds()
	if exited {
		return "", fmt.Errorf("notification dialog died after %.0fs (exit %v): %s", secs10, exitErr, tail)
	}
	return "", fmt.Errorf("notification ran %.0fs with no visible window (wrong desktop/session?) output=%s", secs10, tail)
}

// notifyScript builds the topmost dialog. Split out for marker tests.
func notifyScript(text string, ms int) string {
	return fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing;
$f = New-Object System.Windows.Forms.Form
$f.Text = "RMM Controller"
$f.TopMost = $true
$f.StartPosition = "CenterScreen"
$f.AutoSize = $true
$f.AutoSizeMode = "GrowAndShrink"
$f.MaximizeBox = $false
$f.MinimizeBox = $false
$l = New-Object System.Windows.Forms.Label
$l.Text = "%s"
$l.AutoSize = $true
$l.MaximumSize = New-Object System.Drawing.Size(600, 0)
$l.Padding = New-Object System.Windows.Forms.Padding(24)
$l.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$f.Controls.Add($l)
$b = New-Object System.Windows.Forms.Button
$b.Text = "OK"
$b.DialogResult = "OK"
$b.Dock = "Bottom"
$f.Controls.Add($b)
$f.AcceptButton = $b
if (%d -gt 0) {
  $t = New-Object System.Windows.Forms.Timer
  $t.Interval = %d
  $t.Add_Tick({ $f.Close() })
  $t.Start()
}
$f.Add_Shown({ $f.Activate() | Out-Null; $f.TopMost = $true })
[void]$f.ShowDialog()`, psDQString(text), ms, ms)
}

// speak uses the built-in Windows voice, async in a detached hidden
// powershell (blocking Speak, so the utterance survives our return).
func speak(text string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("usage: speak <text>")
	}
	killSpeakChild()
	script := fmt.Sprintf(`Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak("%s")`, psDQString(text))
	cmd := hideWindow(exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", script))
	if err := cmd.Start(); err != nil {
		return "", err
	}
	_ = os.WriteFile(speakPidFile(), []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	go cmd.Wait()
	return "speaking (async, speak-stop cancels)", nil
}

func speakPidFile() string {
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		return filepath.Join(localApp, "RMM", "speak.pid")
	}
	return filepath.Join(os.TempDir(), "RMM", "speak.pid")
}

func killSpeakChild() {
	b, err := os.ReadFile(speakPidFile())
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
		_ = hideWindow(exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid))).Run()
	}
	_ = os.Remove(speakPidFile())
}

func speakStop() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	killSpeakChild()
	return "speech stopped", nil
}

// psDQString escapes text for a PowerShell double-quoted string.
func psDQString(s string) string {
	r := strings.ReplaceAll(s, "`", "``")
	r = strings.ReplaceAll(r, `"`, `""`)
	r = strings.ReplaceAll(r, "$", "`$")
	return r
}

// getSessionState reports locked/rdp for the remote session so the UI can
// say WHY input does nothing instead of silently dropping it.
// Presence of logonui.exe = secure/lock screen up. TerminalServerSession
// distinguishes RDP from console.
func getSessionState() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	out, err := execPS(`$locked = [bool](Get-Process logonui -ErrorAction SilentlyContinue)
Add-Type -AssemblyName System.Windows.Forms
$rdp = [System.Windows.Forms.SystemInformation]::TerminalServerSession
Write-Output ("locked=" + $locked.ToString().ToLower() + " rdp=" + $rdp.ToString().ToLower())`)
	if err != nil {
		return "", fmt.Errorf("session state unavailable (%s)", firstLine(out))
	}
	return strings.TrimSpace(out), nil
}

// getForegroundWindow returns "process | title" of the focused window —
// what mirror keystrokes would land in. Lightweight (single call) so the
// UI can poll it every couple of seconds while mirroring.
func getForegroundWindow() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	out, err := execPS(`Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class RmmFg {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
}
'@
$h = [RmmFg]::GetForegroundWindow()
$sb = New-Object System.Text.StringBuilder 512
[void][RmmFg]::GetWindowText($h, $sb, 512)
$pid = 0
[void][RmmFg]::GetWindowThreadProcessId($h, [ref]$pid)
try { $pn = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch { $pn = "?" }
Write-Output ("FG: " + $pn + " | " + $sb.ToString())`)
	if err != nil {
		return "", fmt.Errorf("foreground unavailable (%s)", firstLine(out))
	}
	return strings.TrimSpace(out), nil
}

// agentLogPath mirrors the agent's own log locations (see setupLogFile).
func agentLogPath(debug bool) string {
	dir := ""
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	} else {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	if debug {
		return filepath.Join(dir, "agent-debug.log")
	}
	return filepath.Join(dir, "agent.log")
}

// tailFile returns the last n lines (cap 200) for paste-safe log pulls.
func tailFile(path string, n int) (string, error) {
	if n <= 0 {
		n = 60
	}
	if n > 200 {
		n = 200
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n"), nil
}

// getAgentLog pulls the SHORT log (paste-safe by construction).
func getAgentLog(arg string) (string, error) {
	n := 60
	if a := strings.TrimSpace(arg); a != "" {
		if v, err := strconv.Atoi(a); err == nil {
			n = v
		}
	}
	out, err := tailFile(agentLogPath(false), n)
	if err != nil {
		return "", fmt.Errorf("agent log unavailable: %v", err)
	}
	if out == "" {
		return "(log empty)", nil
	}
	return out, nil
}

// getAgentDebugLog pulls the VERBOSE log (paste-safe by construction).
func getAgentDebugLog(arg string) (string, error) {
	n := 60
	if a := strings.TrimSpace(arg); a != "" {
		if v, err := strconv.Atoi(a); err == nil {
			n = v
		}
	}
	out, err := tailFile(agentLogPath(true), n)
	if err != nil {
		return "", fmt.Errorf("debug log unavailable: %v", err)
	}
	if out == "" {
		return "(debug log empty — run with extended logging to fill it)", nil
	}
	return out, nil
}
