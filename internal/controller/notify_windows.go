//go:build windows

package controller

import (
	"syscall"
	"unsafe"
)

func showError(msg string) {
	p1, _ := syscall.UTF16PtrFromString(msg)
	p2, _ := syscall.UTF16PtrFromString("RMM Controller Error")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0,
		uintptr(unsafe.Pointer(p1)), uintptr(unsafe.Pointer(p2)), 0x10)
}
