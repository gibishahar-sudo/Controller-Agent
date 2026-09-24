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
	script, err := trollScript(`C:\m\v.mp4`, ".mp4", 300, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BlockInput($false)",
		"BlockInput($true)",
		"ShowInTaskbar = $false",
		"Topmost = $true",
		"WindowStyle = 'None'",
		"DispatcherTimer",
		"MediaFailed",
		"Add_Closed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("video script missing safety marker %q", want)
		}
	}
	if strings.Contains(script, `"`) {
		// psQuote path uses single quotes; WPF property strings use single.
		// Double quotes would only appear if we broke quoting — still assert
		// the path itself isn't double-quoted.
		if strings.Contains(script, `"C:`) {
			t.Fatalf("path double-quoted: %s", script)
		}
	}

	gscript, err := trollScript(`C:\m\loop.gif`, ".gif", 60, false)
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
