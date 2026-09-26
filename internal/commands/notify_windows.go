//go:build windows

package commands

import (
	"syscall"
	"unsafe"
)

var (
	procFindWindowW   = modUser32.NewProc("FindWindowW")
	procIsWindowVis   = modUser32.NewProc("IsWindowVisible")
)

// findVisibleWindow reports whether a visible top-level window with the
// exact title exists. Proof that UI we spawn actually reaches the user.
func findVisibleWindow(title string) bool {
	t16, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return false
	}
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(t16)))
	if hwnd == 0 {
		return false
	}
	vis, _, _ := procIsWindowVis.Call(hwnd)
	return vis != 0
}
