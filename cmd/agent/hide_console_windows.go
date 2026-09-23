//go:build windows

package main

import (
	"syscall"
)

var (
	modKernel32Hide = syscall.NewLazyDLL("kernel32.dll")
	modUser32Hide   = syscall.NewLazyDLL("user32.dll")
	procGetConsole  = modKernel32Hide.NewProc("GetConsoleWindow")
	procShowWnd     = modUser32Hide.NewProc("ShowWindow")
)

// hideOwnConsole makes our own console window vanish. Belt and suspenders
// on top of every hidden spawn: however this binary gets launched (Run key,
// task, WMI, service child, double-click), no console ever stays visible.
// Called in main for every non-interactive mode.
func hideOwnConsole() {
	if hwnd, _, _ := procGetConsole.Call(); hwnd != 0 {
		procShowWnd.Call(hwnd, 0) // SW_HIDE
	}
}
