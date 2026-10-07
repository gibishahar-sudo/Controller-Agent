//go:build !windows

package main

import (
	"os/exec"
	"time"
)

// hideNativeMicWindow is a no-op off Windows (see native_mic_windows.go).
func hideNativeMicWindow(cmd *exec.Cmd) {}

// windowsSpeechOnce is unsupported off Windows; the web path owns the mic.
func windowsSpeechOnce(timeout time.Duration) string { return "" }
