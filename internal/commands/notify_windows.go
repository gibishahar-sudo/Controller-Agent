//go:build windows

package commands

import (
	"syscall"
	"unsafe"
)

var (
	procFindWindowW     = modUser32.NewProc("FindWindowW")
	procIsWindowVis     = modUser32.NewProc("IsWindowVisible")
	procEnumWindows     = modUser32.NewProc("EnumWindows")
	procGetWndThreadPid = modUser32.NewProc("GetWindowThreadProcessId")
	procGetWindowTextW  = modUser32.NewProc("GetWindowTextW")
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

type ownedWinQuery struct {
	pid   uint32
	title string
	found bool
}

// findVisibleWindowOwned is the strict proof: a VISIBLE window with the
// exact title OWNED by pid. Title-only matching can pass on a stale
// dialog from an earlier call; pid ownership cannot.
func findVisibleWindowOwned(pid uint32, title string) bool {
	q := &ownedWinQuery{pid: pid, title: title}
	cb := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		var wpid uint32
		_, _, _ = procGetWndThreadPid.Call(hwnd, uintptr(unsafe.Pointer(&wpid)))
		if wpid != q.pid {
			return 1 // continue
		}
		buf := make([]uint16, 256)
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			return 1
		}
		if syscall.UTF16ToString(buf[:n]) != q.title {
			return 1
		}
		vis, _, _ := procIsWindowVis.Call(hwnd)
		if vis != 0 {
			q.found = true
			return 0 // stop
		}
		return 1
	})
	_, _, _ = procEnumWindows.Call(cb, 0)
	return q.found
}
