//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// Windows GetCursorPos via user32
var (
	modUser32     = syscall.NewLazyDLL("user32.dll")
	procGetCursor = modUser32.NewProc("GetCursorPos")
)

type point struct {
	X, Y int32
}

func getMousePos() (int, int) {
	var pt point
	ret, _, _ := procGetCursor.Call(uintptr(unsafe.Pointer(&pt)))
	if ret == 0 {
		return 0, 0
	}
	return int(pt.X), int(pt.Y)
}
