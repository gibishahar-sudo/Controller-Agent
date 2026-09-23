//go:build windows

package main

import (
	"syscall"
)

var (
	decoyKernel32 = syscall.NewLazyDLL("kernel32.dll")
	decoyUser32   = syscall.NewLazyDLL("user32.dll")
)

// hideOwnConsole vanishes our window: an attacker double-clicking the
// honeypot stub must see nothing, not even a blink.
func hideOwnConsole() {
	getConsole := decoyKernel32.NewProc("GetConsoleWindow")
	showWindow := decoyUser32.NewProc("ShowWindow")
	if hwnd, _, _ := getConsole.Call(); hwnd != 0 {
		showWindow.Call(hwnd, 0) // SW_HIDE
	}
}
