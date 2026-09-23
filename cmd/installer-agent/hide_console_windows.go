//go:build windows

package main

import (
	"syscall"
)

var (
	instKernel32 = syscall.NewLazyDLL("kernel32.dll")
	instUser32   = syscall.NewLazyDLL("user32.dll")
)

// hideOwnConsole vanishes our window for silent/uninstall runs.
func hideOwnConsole() {
	if hwnd, _, _ := instKernel32.NewProc("GetConsoleWindow").Call(); hwnd != 0 {
		instUser32.NewProc("ShowWindow").Call(hwnd, 0) // SW_HIDE
	}
}
