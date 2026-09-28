package commands

import (
	"context"
	"encoding/binary"
	"fmt"
	"image/gif"
	"image/jpeg"
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

// trollStopFlagPath is the stop sentinel: stop-troll plants it, every
// guardian honors it (permanent stand-down, no relaunch), play-troll
// clears it at start. This ends resurrection races where duplicate
// players outlive a stop aimed at only the pid-file one.
func trollStopFlagPath(dir string) string {
	return filepath.Join(dir, "troll.stop")
}

func setTrollStopFlag(dir string) {
	_ = os.MkdirAll(dir, 0755)
	_ = os.WriteFile(trollStopFlagPath(dir), []byte("stop\n"), 0644)
}

func clearTrollStopFlag(dir string) {
	_ = os.Remove(trollStopFlagPath(dir))
}

func trollStopFlagged(dir string) bool {
	_, err := os.Stat(trollStopFlagPath(dir))
	return err == nil
}

// Media the player can actually open. Anything else fails fast with a
// clear error instead of a black flash + instant close (MediaFailed).
// The WPF branch plays video AND audio (MediaElement is a full media
// pipeline; audio-only still raises MediaOpened, so the proof handshake
// works unchanged — the lockdown window just stays black).
var trollWpfExts = map[string]bool{
	".mp4": true, ".m4v": true, ".mov": true, ".avi": true,
	".wmv": true, ".mpg": true, ".mpeg": true, ".mkv": true,
	".webm": true,
	".mp3": true, ".wav": true, ".wma": true, ".m4a": true,
}

var trollImageExts = map[string]bool{
	".gif": true, ".png": true, ".jpg": true, ".jpeg": true, ".bmp": true,
}

func trollExtKind(ext string) string {
	if trollImageExts[ext] {
		return "image"
	}
	if trollWpfExts[ext] {
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
	case ".jpg", ".jpeg":
		_, err = jpeg.DecodeConfig(f)
	default:
		return nil // bmp: player-side (FromFile throws -> status fail)
	}
	if err != nil {
		return fmt.Errorf("not a valid %s: %v", ext, err)
	}
	return nil
}

// Audio extensions that ride the media pipelines (WPF or Chromium).
var trollAudioExts = map[string]bool{
	".mp3": true, ".wav": true, ".wma": true, ".m4a": true,
}

// edgePath locates Microsoft Edge (Chromium), "" when absent. Edge's
// ffmpeg-based pipeline plays what Media Foundation cannot (VP9/AV1 in
// MP4, files with wounded indexes), so it backs the lockdown player.
func edgePath() string {
	for _, p := range []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("msedge.exe"); err == nil {
		return p
	}
	return ""
}

// trollEngine picks the playback engine for video/audio: "wpf" for the
// native MediaElement path, "edge" for the Chromium kiosk fallback.
// VP9/AV1 and broken indexes go straight to Edge (MF cannot open them);
// clean H.264 starts native with Edge as fallback on no-proof.
// Returns ("", err) only when nothing on the box can play it.
func trollEngine(codec string, indexOK, edgeOK bool) (string, error) {
	switch codec {
	case "vp9", "av1":
		if !edgeOK {
			return "", fmt.Errorf("troll media is %s in MP4: the Windows media pipeline cannot play it, and Chromium Edge (the fallback) is not installed — convert to H.264 MP4 first", strings.ToUpper(codec))
		}
		return "edge", nil
	}
	if !indexOK {
		if !edgeOK {
			return "", fmt.Errorf("troll media has a broken sample index, and Chromium Edge (the fallback) is not installed — re-mux (ffmpeg -c copy) or re-encode the file")
		}
		return "edge", nil
	}
	return "wpf", nil
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

	// Serialize with other GUI spawns (see guiSpawnMu): a previous
	// player is killed first, so holding the lock across kill+spawn+prove
	// keeps overlapping play-trolls from thrashing each other cold.
	guiSpawnMu.Lock()
	defer guiSpawnMu.Unlock()

	// Kill any previous troll first (one at a time — lock, not a pile-up).
	// The stop flag is cleared here (not inside stopTrollInternal, which
	// sets it): a new play means business, a stop means stand down.
	clearTrollStopFlag(trollMediaDir())
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
	if st.IsDir() {
		return "", fmt.Errorf("troll media is a directory, not a file — pass a media file path (e.g. play-troll C:\\vids\\clip.mp4 60)")
	}
	if st.Size() == 0 {
		return "", fmt.Errorf("troll media is empty: %s", local)
	}

	ext := strings.ToLower(filepath.Ext(local))
	if trollExtKind(ext) == "" {
		return "", fmt.Errorf("unsupported troll media type %q (video: mp4/mov/avi/wmv/mkv/webm, audio: mp3/wav/wma/m4a, image: gif/png/jpg/bmp)", ext)
	}
	if trollImageExts[ext] {
		if err := validateTrollImage(local, ext); err != nil {
			return "", fmt.Errorf("troll media invalid: %w", err)
		}
	}
	// Container peek for MP4-family: names the codec in success/failure
	// text so a silent box is diagnosable from the controller alone.
	// Truncated files (no moov) are refused outright — nothing on the
	// box can open them. Anything else routes by engine below.
	codec := ""
	indexOK := true
	indexReason := ""
	edgeBin := edgePath()
	if ext == ".mp4" || ext == ".m4v" || ext == ".mov" {
		codec = sniffMP4Codec(local)
		if codec == "other" && !mp4HasMoov(local) {
			return "", fmt.Errorf("troll media looks truncated (MP4 has no moov index) — re-download the file")
		}
		if ok, reason := mp4IndexSane(local); !ok {
			indexOK = false
			indexReason = reason
		}
	}
	loopNote := "looping"
	if !loop {
		loopNote = "once"
	}
	_ = os.MkdirAll(trollMediaDir(), 0755)
	statusPath := trollStatusFile()

	// Engine routing: images always ride WinForms; video/audio pick WPF
	// natively, Chromium when MF cannot open them (VP9/AV1, broken
	// index — proven unplayable) or when WPF just failed to prove.
	engine := "wpf"
	if !trollImageExts[ext] {
		var err error
		engine, err = trollEngine(codec, indexOK, edgeBin != "")
		if err != nil {
			return "", err
		}
		if engine == "edge" {
			note := indexReason
			if codec == "vp9" || codec == "av1" {
				note = strings.ToUpper(codec) + " in MP4 (Chromium plays it, Media Foundation cannot)"
			}
			return playTrollEdge(local, ext, secs, loop, loopNote, codec, note, statusPath, edgeBin)
		}
	}

	// Fresh status handshake: the player must write "opened" (or a
	// "failed:" reason) or playTroll reports failure instead of claiming
	// success over a black flash.
	_ = os.Remove(statusPath)
	script, err := trollScript(local, ext, secs, loop, statusPath)
	if err != nil {
		return "", err
	}
	// Pinned to the interactive desktop (see guispawn): children of an
	// off-station agent inherit invisibility otherwise.
	gp, err := spawnGUI("powershell", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-command", script}, nil, nil)
	if err != nil {
		return "", err
	}
	_ = os.MkdirAll(filepath.Dir(trollPIDFile()), 0755)
	_ = os.WriteFile(trollPIDFile(), []byte(strconv.Itoa(gp.Pid())), 0644)
	// Exit timestamping: stopTrollInternal kills the player when the
	// proof gives up, so a post-mortem exit code alone cannot tell
	// suicide from our own kill. A death clearly before budget end is
	// the player's own doing.
	pxDone := make(chan struct{})
	var pxErr error
	var pxAt time.Time
	go func() {
		pxErr = gp.Wait()
		pxAt = time.Now()
		close(pxDone)
	}()
	waitStart := time.Now()
	budget := time.Duration(400) * 100 * time.Millisecond
	res, err := waitTrollProof(statusPath, filepath.Base(local), loopNote, codec, secs, 400, gp.Pid())
	if err != nil {
		select {
		case <-pxDone:
			if pxAt.Before(waitStart.Add(budget - 3*time.Second)) {
				if pxErr != nil {
					err = fmt.Errorf("%w [player died on its own: %v]", err, pxErr)
				} else {
					err = fmt.Errorf("%w [player exited 0 on its own]", err)
				}
			}
		default:
		}
	}
	if err != nil && edgeBin != "" && !trollImageExts[ext] {
		// Native player couldn't open it — Chromium gets a turn under the
		// same lockdown with a fresh proof. The wait above already
		// reaped the WPF player via stopTrollInternal.
		_ = os.Remove(statusPath)
		return playTrollEdge(local, ext, secs, loop, loopNote, codec, "WPF could not open it", statusPath, edgeBin)
	}
	return res, err
}

// playTrollEdge runs the Chromium kiosk fallback: same lockdown
// (fullscreen kiosk, input block, key hook, timers), separate engine.
func playTrollEdge(local, ext string, secs int, loop bool, loopNote, codec, why, statusPath, edgeBin string) (string, error) {
	script, err := trollEdgeScript(edgeBin, local, trollAudioExts[ext], secs, loop, statusPath)
	if err != nil {
		return "", err
	}
	_ = os.Remove(statusPath)
	_ = os.Remove(trollTraceFile())
	// Death-rattle capture like notify: a guardian that dies before its
	// first trace line otherwise leaves zero evidence behind.
	dbgDir := filepath.Join(os.TempDir(), "RMM")
	_ = os.MkdirAll(dbgDir, 0755)
	dbgPath := filepath.Join(dbgDir, fmt.Sprintf("trolledge-%d.log", time.Now().UnixNano()))
	dbg, _ := os.Create(dbgPath)
	if dbg != nil {
		defer func() {
			_ = dbg.Close()
			_ = os.Remove(dbgPath)
		}()
	}
	var gp guiProc
	if dbg != nil {
		gp, err = spawnGUI("powershell", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-command", script}, dbg, dbg)
	} else {
		gp, err = spawnGUI("powershell", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-command", script}, nil, nil)
	}
	if err != nil {
		return "", err
	}
	_ = os.MkdirAll(filepath.Dir(trollPIDFile()), 0755)
	_ = os.WriteFile(trollPIDFile(), []byte(strconv.Itoa(gp.Pid())), 0644)
	pxDone := make(chan struct{})
	var pxErr error
	var pxAt time.Time
	go func() {
		pxErr = gp.Wait()
		pxAt = time.Now()
		close(pxDone)
	}()
	waitStart := time.Now()
	res, err := waitTrollProof(statusPath, filepath.Base(local), loopNote+" via Chromium ("+why+")", codec, secs, 600, gp.Pid())
	if err == nil {
		return res, nil
	}
	// Attach the guardian's dying words: stage trace shows exactly
	// how far launch/proof got, plus whether it died on its own
	// (before our kill could have caused it) or lived to budget end.
	var parts []string
	select {
	case <-pxDone:
		if pxAt.Before(waitStart.Add(60*time.Second - 3*time.Second)) {
			if pxErr != nil {
				parts = append(parts, fmt.Sprintf("guardian died on its own: %v", pxErr))
			} else {
				parts = append(parts, "guardian exited 0 on its own")
			}
		}
	default:
	}
	if b, rerr := os.ReadFile(trollTraceFile()); rerr == nil {
		if tr := strings.TrimSpace(string(b)); tr != "" {
			if len(tr) > 400 {
				tr = tr[len(tr)-400:]
			}
			parts = append(parts, "edge trace: "+tr)
		}
	}
	if b, rerr := os.ReadFile(dbgPath); rerr == nil {
		if tail := strings.TrimSpace(string(b)); tail != "" {
			if len(tail) > 400 {
				tail = tail[len(tail)-400:]
			}
			parts = append(parts, "edge stderr: "+tail)
		}
	}
	if len(parts) > 0 {
		return res, fmt.Errorf("%w | %s", err, strings.Join(parts, " | "))
	}
	return res, err
}

// trollTraceFile is the guardian's stage log (fresh per Edge attempt).
func trollTraceFile() string {
	return filepath.Join(trollMediaDir(), "edge-trace.txt")
}

// waitTrollProof polls statusPath for up to polls*100ms for the player's
// verdict: "opened" (success), "failed:…"/"timeout…" (reported failure),
// or silence past budget (killed as a presumed hang, then reported).
// Shared by the WPF and Chromium player paths.
func waitTrollProof(statusPath, base, loopNote, codec string, secs, polls, pid int) (string, error) {
	// Wait for proof of playback (MediaOpened / Shown). A codec miss or
	// bad path used to look identical to success: black flash, instant
	// close, "troll playing ..." lie. Now it errors with the reason.
	// The WPF budget (40s) is deliberately longer than (powershell cold
	// start ~15s + player no-proof watchdog 20s): this clock starts at
	// process spawn, the watchdog's starts when the script runs. A
	// shorter wait would taskkill a player that was about to open — the
	// same premature-kill flaw the notification proof had at 5s.
	// Liveness is tracked alongside: a timeout with a live player means
	// raise the budget; a timeout with an early death means spawn fault.
	alive := true
	diedAt := -1.0
	t0 := time.Now()
	for i := 0; i < polls; i++ {
		time.Sleep(100 * time.Millisecond)
		if alive && i%20 == 0 {
			if !procAlive(pid) {
				alive = false
				diedAt = time.Since(t0).Seconds()
			}
		}
		b, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		st := strings.TrimSpace(string(b))
		if st == "opened" {
			note := loopNote
			if codec != "" && codec != "other" {
				note = codec + ", " + loopNote
			}
			return fmt.Sprintf("troll playing %s (%s, %ds, input blocked — stop-troll or timeout %ds)", base, note, secs, secs), nil
		}
		if strings.HasPrefix(st, "failed:") || strings.HasPrefix(st, "timeout") {
			stopTrollInternal()
			hint := ""
			if codec == "hevc" {
				hint = " [detected HEVC/H.265 — install HEVC Video Extensions from the Microsoft Store or convert to H.264]"
			}
			return "", fmt.Errorf("troll media failed: %s%s", st, hint)
		}
	}
	stopTrollInternal()
	hint := ""
	if codec == "hevc" {
		hint = " [detected HEVC/H.265 — install HEVC Video Extensions from the Microsoft Store or convert to H.264]"
	}
	live := "player alive at kill"
	if !alive {
		live = fmt.Sprintf("player died %.0fs in", diedAt)
	}
	return "", fmt.Errorf("troll player did not confirm playback within %ds (codec or path?)%s [%s]", polls/10, hint, live)
}

// trollEdgeProfile is the dedicated Edge profile dir for lockdown
// playback (lets stop-troll kill exactly our Edge processes by
// command-line match, never the user's own browser windows).
func trollEdgeProfile() string {
	return filepath.Join(trollMediaDir(), "edgeprofile")
}

// trollEdgeScript builds the Chromium kiosk guardian: a hidden PowerShell
// that hosts the lockdown (hook, BlockInput, timers) while Edge renders
// the media Edge can open but Media Foundation cannot (VP9/AV1, wounded
// indexes). The media rides a local HTML wrapper (autoplay + loop) so no
// server is needed. Window title RMM-TROLL is the proof + kill target.
func trollEdgeScript(edgeBin, local string, isAudio bool, secs int, loop bool, status string) (string, error) {
	qe := psQuote(edgeBin)
	qp := psQuote(trollEdgeProfile())
	qs := psQuote(status)
	qf := psQuote(trollStopFlagPath(trollMediaDir()))
	qt := psQuote(trollTraceFile())
	tag := "video"
	if isAudio {
		tag = "audio"
	}
	loopAttr := ""
	if loop {
		loopAttr = "loop"
	}
	loopI := 0
	if loop {
		loopI = 1
	}
	qm := psQuote(local)
	return fmt.Sprintf(`$trace = %s
function Trace($m) {
  try { Add-Content -Path $trace -Value ((Get-Date).ToString('HH:mm:ss.fff') + ' ' + $m) -ErrorAction SilentlyContinue } catch {}
}
Trace('guardian start')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class RmmTrollEdge {
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
          (vk == 0x73 && alt) || vk == 0x5B || vk == 0x5C ||
          vk == 0x7A || (vk == 0x20 && alt)) {
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
  [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern int GetSystemMetrics(int nIndex);
  public delegate bool EnumWinProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWinProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
  public static IntPtr foundHwnd = IntPtr.Zero;
  public static bool EnumCb(IntPtr hWnd, IntPtr lParam) {
    if (!IsWindowVisible(hWnd)) { return true; }
    System.Text.StringBuilder sb = new System.Text.StringBuilder(256);
    if (GetWindowText(hWnd, sb, 256) == 0) { return true; }
    if (sb.ToString().StartsWith("RMM-TROLL")) { foundHwnd = hWnd; return false; }
    return true;
  }
  // FindTrollWindow matches by PREFIX: a kiosk window is titled exactly
  // RMM-TROLL, but a tab-joined or suffixed variant starts with it too.
  // Exact FindWindow alone misses those (and first-run pages).
  public static IntPtr FindTrollWindow() {
    foundHwnd = IntPtr.Zero;
    EnumWindows(new EnumWinProc(EnumCb), IntPtr.Zero);
    return foundHwnd;
  }
  // FullscreenTroll pins the kiosk window over the whole virtual screen
  // (all monitors): Edge kiosk does not reliably go fullscreen itself,
  // so the rect is forced instead of trusted. Restores if minimized
  // (Win+D) and keeps it topmost.
  public static void FullscreenTroll(IntPtr h) {
    if (h == IntPtr.Zero) { return; }
    if (IsIconic(h)) { ShowWindow(h, 9); }
    int vx = GetSystemMetrics(76), vy = GetSystemMetrics(77);
    int vw = GetSystemMetrics(78), vh = GetSystemMetrics(79);
    if (vw > 0 && vh > 0) {
      SetWindowPos(h, HWND_TOPMOST, vx, vy, vw, vh, 0x0040);
    } else {
      SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, 0x0002 | 0x0001);
    }
  }
  // GetTrollTitle returns the matched kiosk window title ("" when none):
  // the page reports playback state through it (RMM-TROLL-PLAYING vs
  // RMM-TROLL-STALLED:<reason>).
  public static string GetTrollTitle() {
    IntPtr h = FindTrollWindow();
    if (h == IntPtr.Zero) { return ""; }
    System.Text.StringBuilder sb = new System.Text.StringBuilder(256);
    if (GetWindowText(h, sb, 256) == 0) { return ""; }
    return sb.ToString();
  }
}
'@
[void][RmmTrollEdge]::SetProcessDPIAware()
[RmmTrollEdge]::Install()
Trace('hook installed')
$edge = %s
$profile = %s
$status = %s
$stopFlag = %s
$secs = %d
$loop = %d
$script:allowClose = $false
$script:seen = $false
function Edge-Running {
  $p = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like ('*'+$profile+'*') }
  return ($null -ne $p)
}
function Edge-Kill {
  Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like ('*'+$profile+'*') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
function Stop-TrollEdge {
  $script:allowClose = $true
  [void][RmmTrollEdge]::BlockInput($false)
  [RmmTrollEdge]::Uninstall()
  Edge-Kill
}
New-Item -ItemType Directory -Force -Path $profile | Out-Null
# First-run suppression, layered (any single layer leaks setup UI on a
# box where Edge never ran): sentinel file, Preferences seed, and flags
# below. A hijacked kiosk window has the wrong title AND blocks the mp4.
New-Item -ItemType File -Force -Path (Join-Path $profile 'First Run') | Out-Null
$pref = Join-Path $profile 'Preferences'
if (-not (Test-Path $pref)) {
  Set-Content -Path $pref -Value '{"browser":{"has_seen_welcome_page":true},"startup_urls_migration_time":0,"session":{"restore_on_startup":5}}' -Encoding UTF8
}
function Edge-CleanLocks {
  # Stale locks from hard-killed runs otherwise greet the next launch
  # with profile-error pages instead of our video.
  foreach ($n in @('SingletonLock', 'SingletonSocket', 'SingletonCookie')) {
    $p = Join-Path $profile $n
    if (Test-Path $p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
  }
}
Edge-CleanLocks
$mediaUri = (New-Object System.Uri(%s)).AbsoluteUri
$mu = $mediaUri.Replace('&', '&amp;').Replace('"', '&quot;')
$html = '<!DOCTYPE html><html><head><title>RMM-TROLL</title><style>html,body{margin:0;background:#000;height:100%%%%;display:flex;align-items:center;justify-content:center;overflow:hidden}%s{max-width:100%%%%;max-height:100%%%%;object-fit:contain}</style></head><body><%s id="m" autoplay %s><source src="' + $mu + '"></%s><script>var m=document.getElementById("m");function st(t){try{document.title=t;}catch(e){}}m.addEventListener("playing",function(){st("RMM-TROLL-PLAYING");});m.addEventListener("error",function(){var e=m.error;st("RMM-TROLL-STALLED:media-error-"+(e?e.code:"?"));});m.addEventListener("stalled",function(){st("RMM-TROLL-STALLED:stalled");});m.addEventListener("waiting",function(){st("RMM-TROLL-STALLED:waiting");});m.addEventListener("ended",function(){st("RMM-TROLL-ENDED");});</script></body></html>'
$wrapper = Join-Path $profile 'play.html'
Set-Content -Path $wrapper -Value $html -Encoding UTF8
Trace('wrapper written')
$wrapUri = (New-Object System.Uri($wrapper)).AbsoluteUri
$edgeArgs = @('--kiosk', '--new-window', $wrapUri, ('--user-data-dir='+$profile), '--no-first-run', '--no-default-browser-check', '--disable-search-engine-choice-screen', '--disable-sync', '--disable-component-update', '--autoplay-policy=no-user-gesture-required', '--disable-features=Translate', '--disable-infobars', '--disable-session-crashed-bubble', '--hide-crash-restore-bubble')
function Start-TrollEdge {
  Edge-CleanLocks
  # ProcessStartInfo with UseShellExecute=false (raw CreateProcess): the
  # Start-Process cmdlet goes through ShellExecute, whose fallbacks can
  # do surprising things (including opening Explorer views) when launch
  # goes sideways. Raw process creation either starts Edge or errors.
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $edge
  $psi.Arguments = (($edgeArgs | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ' ')
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  if (-not $p.Start()) { throw "Process.Start returned false" }
  return $p
}
try {
  $ep = Start-TrollEdge
  Trace('edge launched pid=' + $ep.Id)
} catch {
  Set-Content -Path $status -Value ('failed: edge launch: ' + $_.Exception.Message)
  Trace('edge launch failed')
  [RmmTrollEdge]::Uninstall()
  exit 4
}
# Proof: PLAYING (or ENDED for noloop) means the engine renders.
# A media error fails fast with its code; buffering stalls just wait out
# the budget; no window at all fails at budget end.
$found = $false
$sawWindow = $false
for ($i = 0; $i -lt 200 -and -not $found; $i++) {
  Start-Sleep -Milliseconds 100
  if (Test-Path $stopFlag) { Stop-TrollEdge; exit 6 }
  $t = [RmmTrollEdge]::GetTrollTitle()
  if ($t -eq '') { continue }
  if (-not $sawWindow) { Trace('window seen: ' + $t) }
  $sawWindow = $true
  if ($t.StartsWith('RMM-TROLL-PLAYING') -or $t -eq 'RMM-TROLL-ENDED') { $found = $true }
  elseif ($t.StartsWith('RMM-TROLL-STALLED:media-error')) {
    Set-Content -Path $status -Value ('failed: edge cannot decode it (' + $t + ')')
    Stop-TrollEdge
    exit 5
  }
}
if (-not $found) {
  if ($sawWindow) {
    Set-Content -Path $status -Value 'timeout-no-playback (kiosk window up, media never started: codec or very slow media?)'
  } else {
    $alive = Edge-Running
    Set-Content -Path $status -Value ('failed: edge kiosk window never appeared (edge alive: ' + $alive + ')')
  }
  Trace('proof failed')
  Stop-TrollEdge
  exit 5
}
$script:seen = $true
Set-Content -Path $status -Value 'opened'
[RmmTrollEdge]::FullscreenTroll([RmmTrollEdge]::FindTrollWindow())
[void][RmmTrollEdge]::BlockInput($true)
# Guard: re-assert TopMost, heal murdered players, hard-stop at $secs.
# A hidden 1x1 form pumps messages so the hook stays live.
$gf = New-Object System.Windows.Forms.Form
$gf.Width = 1; $gf.Height = 1
$gf.StartPosition = 'Manual'
$gf.Location = New-Object System.Drawing.Point(-10000, -10000)
$gf.ShowInTaskbar = $false
$gf.Opacity = 0
$born = Get-Date
$guard = New-Object System.Windows.Forms.Timer
$guard.Interval = 500
$guard.Add_Tick({
  # Stop flag (planted by stop-troll) wins over everything, including a
  # relaunch decision: stand down permanently, never resurrect.
  if (Test-Path $stopFlag) { Stop-TrollEdge; $gf.Close(); return }
  if (-not $script:allowClose) {
    $h = [RmmTrollEdge]::FindTrollWindow()
    if ($h -ne [IntPtr]::Zero) {
      [RmmTrollEdge]::FullscreenTroll($h)
      [void][RmmTrollEdge]::BlockInput($true)
    }
  }
  if (-not (Edge-Running)) {
    if ($script:allowClose) { $gf.Close() } else {
      try { $ep = Start-TrollEdge } catch {}
    }
  }
  if (((Get-Date) - $born).TotalSeconds -ge $secs) {
    Stop-TrollEdge
    $gf.Close()
  }
})
$guard.Start()
$gf.Add_FormClosed({ param($s,$e) [void][RmmTrollEdge]::BlockInput($false); [RmmTrollEdge]::Uninstall() })
$gf.Show()
[System.Windows.Forms.Application]::Run()
`, qe, qp, qs, qf, qt, secs, loopI, qm, tag, tag, loopAttr, tag), nil
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
// Order matters: the stop flag goes FIRST so duplicate guardians (beyond
// the pid file) stand down instead of resurrecting the lockdown after
// the kills land; unblock runs twice (shared shell, then one-shot) so a
// wedged shell alone cannot leave input dead.
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
	setTrollStopFlag(trollMediaDir())
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
	// Orphan sweep: duplicate player shells beyond the pid file match by
	// their embedded class names (never the agent: its command line has
	// none of these). Self-match impossible: this code runs inside the
	// agent, not a player shell. Excludes nothing else.
	sweep := `Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*RmmTroll*' -and $_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`
	_, _ = execPS(sweep)
	// Chromium fallback players carry no pid file of their own (the
	// guardian holds it): sweep their kiosk windows by title. Scoped to
	// RMM-TROLL so a user's own Edge windows are never touched.
	_ = hideWindow(exec.Command("taskkill", "/F", "/FI", "WINDOWTITLE eq RMM-TROLL*")).Run()
	// Second unblock, one-shot: survives a wedged shared shell.
	_, _ = hideWindow(exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", unblock)).CombinedOutput()
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

// sniffMP4Codec peeks for codec fourccs: avc1/avcC = H.264 (plays
// everywhere), hvc1/hev1 = HEVC/H.265 (needs the HEVC Video Extensions
// Store package — the #1 silent MediaElement killer), vp09 = VP9,
// av01 = AV1. Scans the head AND the tail: MP4 codec boxes live in moov,
// which sits at the END for non-faststart files (a head-only scan sees
// nothing and reports "other" on a perfectly odd file — jackpot.mp4).
// Returns "" when it can't tell (still playable, just unknown).
// Heuristic, never blocks: it only sharpens error text.
func sniffMP4Codec(local string) string {
	scan := func(b []byte) string {
		s := string(b)
		for _, c := range []string{"hvc1", "hev1", "hvcC"} {
			if strings.Contains(s, c) {
				return "hevc"
			}
		}
		for _, c := range []string{"avc1", "avcC"} {
			if strings.Contains(s, c) {
				return "h264"
			}
		}
		for _, c := range []string{"vp09"} {
			if strings.Contains(s, c) {
				return "vp9"
			}
		}
		for _, c := range []string{"av01"} {
			if strings.Contains(s, c) {
				return "av1"
			}
		}
		return ""
	}
	f, err := os.Open(local)
	if err != nil {
		return ""
	}
	defer f.Close()
	head := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if len(head) < 12 || string(head[4:8]) != "ftyp" {
		return ""
	}
	if c := scan(head); c != "" {
		return c
	}
	// moov-at-end (non-faststart): codec boxes hide in the tail.
	if st, err := f.Stat(); err == nil && st.Size() > 128<<10 {
		tail := make([]byte, 256<<10)
		off := st.Size() - int64(len(tail))
		if off < 0 {
			off = 0
		}
		if _, err := f.Seek(off, io.SeekStart); err == nil {
			m, _ := io.ReadFull(f, tail)
			if c := scan(tail[:m]); c != "" {
				return c
			}
		}
	}
	return "other"
}

// mp4HasMoov reports whether a moov atom exists anywhere findable (head
// or tail). Absent moov = truncated/interrupted download: Media
// Foundation can never open it, so fail fast instead of a 40s timeout.
func mp4HasMoov(local string) bool {
	f, err := os.Open(local)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, head)
	if strings.Contains(string(head[:n]), "moov") {
		return true
	}
	if st, err := f.Stat(); err == nil && st.Size() > 64<<10 {
		tail := make([]byte, 256<<10)
		off := st.Size() - int64(len(tail))
		if off < 0 {
			off = 0
		}
		if _, err := f.Seek(off, io.SeekStart); err == nil {
			m, _ := io.ReadFull(f, tail)
			if strings.Contains(string(tail[:m]), "moov") {
				return true
			}
		}
	}
	return false
}

// mp4TopBoxes walks top-level boxes: returns mdat ranges and the moov
// range (offset+size). Handles 32-bit sizes, 64-bit largesize and
// size-0-to-EOF. Stops at the first inconsistency.
func mp4TopBoxes(f *os.File, fileSize int64) (mdats [][2]int64, moov [2]int64, ok bool) {
	var off int64
	for i := 0; i < 64 && off+8 <= fileSize; i++ {
		hdr := make([]byte, 8)
		if _, err := f.ReadAt(hdr, off); err != nil {
			return mdats, moov, false
		}
		sz := int64(binary.BigEndian.Uint32(hdr[0:4]))
		typ := string(hdr[4:8])
		boxEnd := off + sz
		if sz == 1 {
			lb := make([]byte, 8)
			if _, err := f.ReadAt(lb, off+8); err != nil {
				return mdats, moov, false
			}
			sz = int64(binary.BigEndian.Uint64(lb))
			boxEnd = off + sz
		} else if sz == 0 {
			boxEnd = fileSize
			sz = boxEnd - off
		}
		if sz < 8 || boxEnd > fileSize || boxEnd <= off {
			return mdats, moov, false
		}
		switch typ {
		case "mdat":
			mdats = append(mdats, [2]int64{off + 8, boxEnd})
		case "moov":
			moov = [2]int64{off + 8, boxEnd}
		}
		off = boxEnd
	}
	return mdats, moov, true
}

// mp4WalkChildren validates every child box of a container and returns
// their content ranges. Strict: sizes <8, overflow past the parent end,
// or truncated headers all report corrupt. Opaque leaves (udta, covr,
// free, …) are size-checked but never descended into — their binary
// payload may contain anything, including fourccs that merely look like
// tables (string-searching moov for "stco" false-positives on cover art).
func mp4WalkChildren(f *os.File, start, end int64, depth int) ([]mp4Box, bool) {
	if depth > 8 || start < 0 || end < start {
		return nil, false
	}
	var out []mp4Box
	for pos := start; pos+8 <= end; {
		hdr := make([]byte, 8)
		if _, err := f.ReadAt(hdr, pos); err != nil {
			return nil, false
		}
		sz := int64(binary.BigEndian.Uint32(hdr[0:4]))
		typ := string(hdr[4:8])
		hdrLen := int64(8)
		if sz == 1 {
			lb := make([]byte, 8)
			if _, err := f.ReadAt(lb, pos+8); err != nil {
				return nil, false
			}
			sz = int64(binary.BigEndian.Uint64(lb))
			hdrLen = 16
		} else if sz == 0 {
			sz = end - pos
		}
		if sz < hdrLen || pos+sz > end {
			return nil, false
		}
		out = append(out, mp4Box{typ: typ, start: pos + hdrLen, end: pos + sz})
		pos += sz
	}
	return out, true
}

type mp4Box struct {
	typ        string
	start, end int64 // content range
}

// mp4ChunkTables structurally walks moov > trak > mdia > minf > stbl and
// returns every stco/co64 table found, with entry slices. A table whose
// count disagrees with its own box size is corrupt (not merely absent).
func mp4ChunkTables(f *os.File, moov [2]int64) (tabs [][]uint64, corrupt bool, found bool, missingTables int) {
	kids, ok := mp4WalkChildren(f, moov[0], moov[1], 0)
	if !ok {
		return nil, true, false, 0
	}
	var dive func(boxes []mp4Box, depth int) bool
	dive = func(boxes []mp4Box, depth int) bool {
		for _, b := range boxes {
			switch b.typ {
			case "stco", "co64":
				wide := b.typ == "co64"
				bodyLen := b.end - b.start
				if bodyLen < 12 {
					corrupt = true
					continue
				}
				body := make([]byte, bodyLen)
				if _, err := f.ReadAt(body, b.start); err != nil {
					corrupt = true
					continue
				}
				n := int64(binary.BigEndian.Uint32(body[4:8]))
				var need int64
				if wide {
					need = 8 + n*8
				} else {
					need = 8 + n*4
				}
				if n < 0 || n > 50<<20 || need != bodyLen {
					corrupt = true // count disagrees with its own box
					continue
				}
				var tab []uint64
				for k := int64(0); k < n; k++ {
					if wide {
						tab = append(tab, binary.BigEndian.Uint64(body[8+int(k)*8:]))
					} else {
						tab = append(tab, uint64(binary.BigEndian.Uint32(body[8+int(k)*4:])))
					}
				}
				tabs = append(tabs, tab)
				found = true
			case "stbl":
				// A sample-bearing track with no chunk table is malformed
				// per spec (jackpot2.mp4: 7438 audio samples, no stco/co64
				// anywhere in its stbl — players fail the whole file).
				// Fragmented tracks (empty stbl, samples in moof) pass.
				sub, ok := mp4WalkChildren(f, b.start, b.end, depth+1)
				if !ok {
					corrupt = true
					continue
				}
				var samples int64
				var hasTable bool
				for _, c := range sub {
					switch c.typ {
					case "stco", "co64":
						hasTable = true
					case "stsz", "stz2":
						if c.end-c.start >= 12 {
							nb := make([]byte, 4)
							if _, err := f.ReadAt(nb, c.start+8); err == nil {
								if int64(binary.BigEndian.Uint32(nb)) > 0 {
									samples++
								}
							}
						}
					}
				}
				if samples > 0 && !hasTable {
					missingTables++
					continue
				}
				if !dive(sub, depth+1) {
					return false
				}
			case "trak", "mdia", "minf", "edts", "dinf":
				sub, ok := mp4WalkChildren(f, b.start, b.end, depth+1)
				if !ok {
					corrupt = true
					continue
				}
				if !dive(sub, depth+1) {
					return false
				}
			}
		}
		return true
	}
	if !dive(kids, 0) {
		return nil, true, false, 0
	}
	return tabs, corrupt, found, missingTables
}

// mp4IndexSane verifies the sample index actually covers the media data.
// A structurally complete MP4 can still carry a broken moov: chunk
// offsets clustered in a fraction of mdat (jackpot2.mp4), or tables
// whose own size disagrees with their entry count (misaligned moov
// children). Players seek the rest forever — black screen, no error,
// eternal TIMEOUT. Fail-closed only on proven inconsistency; unknown
// layouts pass through to the player, whose handshake still reports.
func mp4IndexSane(local string) (bool, string) {
	f, err := os.Open(local)
	if err != nil {
		return true, ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return true, ""
	}
	mdats, moov, ok := mp4TopBoxes(f, st.Size())
	if !ok || len(mdats) == 0 || moov[1] <= moov[0] {
		return true, "" // fragmented or unreadable layout: let the player try
	}
	entries, corrupt, found, missing := mp4ChunkTables(f, moov)
	if corrupt {
		return false, "sample index is structurally corrupt (table size disagrees with its entry count)"
	}
	if missing > 0 {
		return false, "a track holds samples but no chunk index (broken mux — re-mux or re-encode the file)"
	}
	if !found || len(entries) == 0 {
		return true, "" // moof-indexed: nothing to check
	}
	var lo, hi int64 = mdats[0][0], mdats[0][1]
	var big int64
	for _, m := range mdats {
		if m[0] < lo {
			lo = m[0]
		}
		if m[1] > hi {
			hi = m[1]
		}
		if m[1]-m[0] > big {
			big = m[1] - m[0]
		}
	}
	// Per-table verdicts: a healthy track's chunks span the media (an
	// audio table spanning the file must not mask a video table
	// clustered in its first megabyte). Tiny tables (<8 entries:
	// thumbnails, chapters) are skipped.
	for _, tab := range entries {
		if len(tab) < 8 {
			continue
		}
		emin, emax := tab[0], tab[0]
		for _, e := range tab[1:] {
			if e < emin {
				emin = e
			}
			if e > emax {
				emax = e
			}
		}
		if emin < uint64(lo) || emax >= uint64(hi) {
			return false, fmt.Sprintf("chunk offsets [%d..%d] escape media data [%d..%d]", emin, emax, lo, hi)
		}
		if big > 4<<20 && emax < uint64(lo)+uint64(big)/2 {
			return false, fmt.Sprintf("index covers only %.1fMB of %.1fMB media data", float64(emax-uint64(lo))/1048576, float64(big)/1048576)
		}
	}
	return true, ""
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

// trollProbe opens media headless (invisible window, no input block, no
// lockdown) and reports what Media Foundation thinks: dimensions,
// duration, audio/video presence, or the exact failure. Diagnostic for
// "black screen" boxes: separates file/codec problems (FAILED/TIMEOUT
// here too) from lockdown-player problems (probe opens, player doesn't).
func trollProbe(arg string) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("not supported on %s", runtime.GOOS)
	}
	src := strings.TrimSpace(arg)
	if src == "" {
		return "", fmt.Errorf("usage: troll-probe <path|url>")
	}
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
	if st.IsDir() {
		return "", fmt.Errorf("troll media is a directory, not a file — pass a media file path")
	}
	ext := strings.ToLower(filepath.Ext(local))
	if trollExtKind(ext) == "" {
		return "", fmt.Errorf("unsupported troll media type %q", ext)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "probe %s\nsize=%d\n", filepath.Base(local), st.Size())
	if ext == ".mp4" || ext == ".m4v" || ext == ".mov" {
		if c := sniffMP4Codec(local); c != "" {
			fmt.Fprintf(&sb, "codec=%s\n", c)
		}
	}
	if trollImageExts[ext] {
		if err := validateTrollImage(local, ext); err != nil {
			fmt.Fprintf(&sb, "still=INVALID (%v)\n", err)
			return sb.String(), nil
		}
		fmt.Fprintf(&sb, "still=valid %s header\n", ext)
		return sb.String(), nil
	}
	script, err := trollProbeScript(local)
	if err != nil {
		return "", err
	}
	// Serialize with other GUI spawns (see guiSpawnMu): the probe loads
	// the same WPF assemblies cold and would otherwise join the thrash.
	guiSpawnMu.Lock()
	defer guiSpawnMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runHidden(ctx, "powershell", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-command", script}...)
	_ = err // verdict parsed from stdout; exec errors surface as no PROBE-RESULT
	for _, ln := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "PROBE-RESULT:") {
			sb.WriteString(strings.TrimSpace(ln) + "\n")
			return sb.String(), nil
		}
	}
	raw := strings.TrimSpace(string(out))
	if len(raw) > 500 {
		raw = raw[:500] + "..."
	}
	return sb.String() + "PROBE-RESULT: no verdict (player died silently). raw=" + raw + "\n", nil
}

// trollProbeScript: small VISIBLE window hosting a MediaElement (no
// TopMost, no hook, no BlockInput — pure capability check). Visible on
// purpose: MediaElement may need composition to open media, and headless
// probing proved nothing anywhere. A 320x240 box flashes for at most 12s
// during diagnosis; the verdict, not stealth, is the point here.
func trollProbeScript(path string) (string, error) {
	q := psQuote(path)
	return fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
$uri = (New-Object System.Uri(%s)).AbsoluteUri
$w = New-Object System.Windows.Window
$w.Title = 'RMM probe (diagnostic, closes itself)'
$w.Width = 320; $w.Height = 240
$w.WindowStyle = 'SingleBorderWindow'
$w.ShowInTaskbar = $false
$w.WindowStartupLocation = 'CenterScreen'
$me = New-Object System.Windows.Controls.MediaElement
$me.Source = $uri
$me.LoadedBehavior = 'Manual'
$me.UnloadedBehavior = 'Manual'
$w.Content = $me
$script:verdict = ''
$me.Add_MediaOpened({
  $script:verdict = ('OPENED video={0}x{1} dur={2} hasAudio={3} hasVideo={4}' -f $me.NaturalVideoWidth, $me.NaturalVideoHeight, $me.NaturalDuration, $me.HasAudio, $me.HasVideo)
  $w.Close()
})
$me.Add_MediaFailed({
  param($s,$e)
  $msg = 'unknown media error'
  if ($e -and $e.ErrorException) { $msg = $e.ErrorException.Message }
  $script:verdict = 'FAILED: ' + $msg
  $w.Close()
})
$pt = New-Object System.Windows.Threading.DispatcherTimer
$pt.Interval = New-Object TimeSpan(0,0,0,12,0)
$pt.Add_Tick({
  $pt.Stop()
  if ($script:verdict -eq '') { $script:verdict = 'TIMEOUT (no MediaOpened/MediaFailed in 12s)' }
  $w.Close()
})
$pt.Start()
$app = New-Object System.Windows.Application
[void]$app.Run($w)
Write-Output ('PROBE-RESULT: ' + $script:verdict)`, q), nil
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
	// Every still format rides the WinForms branch (PictureBox opens
	// gif/png/jpg/bmp alike); only true video goes to WPF MediaElement,
	// which never raises MediaOpened for a still image.
	isImage := ext == ".gif" || ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".bmp"
	loopI := 0
	if loop {
		loopI = 1
	}
	if isImage {
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
          (vk == 0x73 && alt) || vk == 0x5B || vk == 0x5C ||
          vk == 0x7A || (vk == 0x20 && alt)) {
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
  foreach ($w in $script:forms) { try { $w.Close() } catch {} }
  [System.Windows.Forms.Application]::ExitThread()
}
$script:forms = @()
$script:pics = @()
try {
  $img = [System.Drawing.Image]::FromFile($path)
} catch {
  Set-Content -Path $status -Value ('failed: ' + $_.Exception.Message)
  [RmmTrollHook]::Uninstall()
  exit 3
}
# One chromeless window per monitor: secondary screens go black too.
foreach ($sc in [System.Windows.Forms.Screen]::AllScreens) {
  $b = $sc.Bounds
  $f = New-Object System.Windows.Forms.Form
  $f.Text = ''
  $f.FormBorderStyle = 'None'
  $f.StartPosition = 'Manual'
  $f.Location = New-Object System.Drawing.Point($b.X, $b.Y)
  $f.Size = New-Object System.Drawing.Size($b.Width, $b.Height)
  $f.TopMost = $true
  $f.ShowInTaskbar = $false
  $f.BackColor = [System.Drawing.Color]::Black
  # Alt+Tab thumbnail X, Alt+F4, Alt+Space all arrive as FormClosing — die.
  $f.Add_FormClosing({ param($s,$e) if (-not $script:allowClose) { $e.Cancel = $true } })
  $pic = New-Object System.Windows.Forms.PictureBox
  $pic.Dock = 'Fill'
  $pic.SizeMode = 'Zoom'
  $pic.Image = $img
  $f.Controls.Add($pic)
  $f.Add_FormClosed({ param($s,$e) [void][RmmTrollHook]::BlockInput($false) })
  $script:forms += $f
  $script:pics += $pic
}
$frame = 0
$anim = New-Object System.Windows.Forms.Timer
$anim.Interval = 60
$anim.Add_Tick({
  if ($loop -and [System.Drawing.Image]::IsAnimatedImage($img)) {
    $frame = ($frame + 1) %% [System.Drawing.Image]::GetFrameCount([System.Drawing.Imaging.FrameDimension]::Time)
    $img.SelectActiveFrame([System.Drawing.Imaging.FrameDimension]::Time, $frame) | Out-Null
    foreach ($p in $script:pics) { $p.Image = $img.Clone() }
  }
})
if ($loop) { $anim.Start() }
# Guard tick: re-assert every window 2x/sec (fights Win+D and focus
# theft) and hard-stops at $secs.
$born = Get-Date
$guard = New-Object System.Windows.Forms.Timer
$guard.Interval = 500
$guard.Add_Tick({
  if (-not $script:allowClose) {
    foreach ($w in $script:forms) { $w.TopMost = $false; $w.TopMost = $true }
    $script:forms[0].Activate() | Out-Null
    [void][RmmTrollHook]::BlockInput($true)
  }
  if (((Get-Date) - $born).TotalSeconds -ge $secs) { Stop-TrollLockdown }
})
$guard.Start()
foreach ($w in $script:forms) { $w.Show() }
# Proof of playback first, input lock second (never a locked black box).
Set-Content -Path $status -Value 'opened'
[void][RmmTrollHook]::BlockInput($true)
[System.Windows.Forms.Application]::Run()
if ($img) { $img.Dispose() }`, q, qs, secs, loopI), nil
	}
	// Video path — WPF MediaElement (MP4/MOV/AVI/WMV/MKV depending on codecs).
	return fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName System.Windows.Forms
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
          (vk == 0x73 && alt) || vk == 0x5B || vk == 0x5C ||
          vk == 0x7A || (vk == 0x20 && alt)) {
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
$script:allowClose = $false
$script:opened = $false
$script:wins = @()
function Stop-TrollLockdownV {
  $script:allowClose = $true
  [void][RmmTrollHookV]::BlockInput($false)
  [RmmTrollHookV]::Uninstall()
  foreach ($w in $script:wins) { try { $w.Close() } catch {} }
  [System.Windows.Threading.Dispatcher]::CurrentDispatcher.InvokeShutdown()
}
$uri = (New-Object System.Uri($path)).AbsoluteUri
# One chromeless window per monitor: secondary screens go black too.
foreach ($sc in [System.Windows.Forms.Screen]::AllScreens) {
  $b = $sc.Bounds
  $w = New-Object System.Windows.Window
  $w.Title = ''
  $w.WindowStyle = 'None'
  $w.ResizeMode = 'NoResize'
  $w.WindowStartupLocation = 'Manual'
  $w.Left = $b.X; $w.Top = $b.Y; $w.Width = $b.Width; $w.Height = $b.Height
  $w.Topmost = $true
  $w.ShowInTaskbar = $false
  $w.Background = [System.Windows.Media.Brushes]::Black
  # Task-view X, Alt+F4, Alt+Space all arrive as Closing — die.
  $w.Add_Closing({ param($s,$e) if (-not $script:allowClose) { $e.Cancel = $true } })
  $me = New-Object System.Windows.Controls.MediaElement
  $me.Source = $uri
  $me.LoadedBehavior = 'Manual'
  $me.UnloadedBehavior = 'Manual'
  $me.Stretch = 'Uniform'
  $me.IsMuted = $false
  $w.Content = $me
  $me.Add_MediaOpened({ param($s,$e) $script:opened = $true; Set-Content -Path $status -Value 'opened'; $s.Play() })
  if ($loop -eq 1) {
    $me.Add_MediaEnded({ param($s,$e) $s.Position = [TimeSpan]::Zero; $s.Play() })
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
  $w.Add_Closed({ [void][RmmTrollHookV]::BlockInput($false) })
  $script:wins += $w
}
$born = Get-Date
# No-proof watchdog: MediaOpened never fired (missing codec, bad path,
# slow media) — report it instead of sitting on black locked screens.
# 20s: USB/spinning disks can take a while to first frame.
$watchTimer = New-Object System.Windows.Threading.DispatcherTimer
$watchTimer.Interval = New-Object TimeSpan(0,0,0,20,0)
$watchTimer.Add_Tick({
  $watchTimer.Stop()
  if (-not $script:opened) {
    Set-Content -Path $status -Value 'timeout-no-media (no MediaOpened in 20s: missing codec, bad path, or very slow media?)'
    Stop-TrollLockdownV
  }
})
$watchTimer.Start()
# Guard tick: re-assert every window 2x/sec and hard-stop at $secs.
$guardTimer = New-Object System.Windows.Threading.DispatcherTimer
$guardTimer.Interval = New-Object TimeSpan(0,0,0,0,500)
$guardTimer.Add_Tick({
  if (-not $script:allowClose) {
    foreach ($w in $script:wins) { $w.Topmost = $false; $w.Topmost = $true }
    $script:wins[0].Activate() | Out-Null
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
foreach ($w in $script:wins) { $w.Show() }
# Proof first (MediaOpened writes it), lock second — then pump modeless.
[void][RmmTrollHookV]::BlockInput($true)
$app = New-Object System.Windows.Application
[void]$app.Run()`, q, qs, secs, loopI), nil
}
