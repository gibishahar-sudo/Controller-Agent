//go:build windows

package main

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// hideNativeMicWindow spawns the listener with no console flash.
func hideNativeMicWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

// windowsSpeechOnce runs one blocking Windows Speech Recognition pass
// (System.Speech, in-box since Vista — no downloads, no cloud) and returns
// the transcript, "" when nothing was heard. The caller runs it off the UI
// thread with its own overall timeout; the recognition itself is bounded by
// initial/end silence timeouts so a quiet room always resolves.
func windowsSpeechOnce(timeout time.Duration) string {
	ps := `Add-Type -AssemblyName System.Speech;` +
		`$rec = New-Object System.Speech.Recognition.SpeechRecognitionEngine([System.Globalization.CultureInfo]::GetCultureInfo('en-US'));` +
		`$rec.LoadGrammar((New-Object System.Speech.Recognition.DictationGrammar));` +
		`$rec.InitialSilenceTimeout = [TimeSpan]::FromSeconds(8);` +
		`$rec.EndSilenceTimeout = [TimeSpan]::FromSeconds(1.5);` +
		`try { $rec.SetInputToDefaultAudioDevice(); } catch { exit 2 };` +
		`try { $r = $rec.Recognize(); } catch { exit 3 };` +
		`if ($r -ne $null) { $r.Text }`
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	// No console window: the listener runs beside a GUI with no flash.
	hideNativeMicWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
