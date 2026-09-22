//go:build windows

package commands

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	procSetPos  = modUser32.NewProc("SetCursorPos")
	procMouseEv = modUser32.NewProc("mouse_event")
	procGetPos  = modUser32.NewProc("GetCursorPos")
)

type point struct{ X, Y int32 }

func getMousePos() (int, int) {
	var pt point
	ret, _, _ := procGetPos.Call(uintptr(unsafe.Pointer(&pt)))
	if ret == 0 {
		return 0, 0
	}
	return int(pt.X), int(pt.Y)
}

func mouseMove(arg string) (string, error) {
	parts := strings.Split(arg, ",")
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: mouse-move <x>,<y>")
	}
	var x, y int
	fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &x)
	fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &y)
	procSetPos.Call(uintptr(x), uintptr(y))
	return fmt.Sprintf("moved to %d,%d", x, y), nil
}

func mouseClick(_ string) (string, error) {
	const MOUSEEVENTF_LEFTDOWN = 0x0002
	const MOUSEEVENTF_LEFTUP = 0x0004
	procMouseEv.Call(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
	procMouseEv.Call(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
	return "clicked", nil
}

func mouseDoubleClick() (string, error) {
	mouseClick("")
	time.Sleep(50 * time.Millisecond)
	return mouseClick("")
}

func parseXY(arg string) (int, int, error) {
	parts := strings.Split(arg, ",")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("usage: <x>,<y>")
	}
	var x, y int
	fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &x)
	fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &y)
	return x, y, nil
}

// mouseClickAt moves then clicks atomically: one command round trip
// instead of two (mouse-move + mouse-click) on high-latency relays.
func mouseClickAt(arg string) (string, error) {
	x, y, err := parseXY(arg)
	if err != nil {
		return "", fmt.Errorf("mouse-click-at %v", err)
	}
	procSetPos.Call(uintptr(x), uintptr(y))
	return mouseClick("")
}

// mouseDoubleClickAt moves then double-clicks atomically.
func mouseDoubleClickAt(arg string) (string, error) {
	x, y, err := parseXY(arg)
	if err != nil {
		return "", fmt.Errorf("mouse-doubleclick-at %v", err)
	}
	procSetPos.Call(uintptr(x), uintptr(y))
	return mouseDoubleClick()
}

func mouseButton(arg string) (string, error) {
	parts := strings.Fields(strings.ToLower(arg))
	if len(parts) < 2 {
		return "", fmt.Errorf("usage: mouse-button <left|right|middle> <down|up>")
	}
	var down, up uintptr
	switch parts[0] {
	case "left":
		down, up = 0x0002, 0x0004
	case "right":
		down, up = 0x0008, 0x0010
	case "middle":
		down, up = 0x0020, 0x0040
	default:
		return "", fmt.Errorf("unknown button %s", parts[0])
	}
	if parts[1] == "down" {
		procMouseEv.Call(down, 0, 0, 0, 0)
	} else {
		procMouseEv.Call(up, 0, 0, 0, 0)
	}
	return fmt.Sprintf("%s %s", parts[0], parts[1]), nil
}

func mouseScroll(arg string) (string, error) {
	var delta int
	fmt.Sscanf(arg, "%d", &delta)
	const MOUSEEVENTF_WHEEL = 0x0800
	procMouseEv.Call(MOUSEEVENTF_WHEEL, 0, 0, uintptr(delta*120), 0)
	return fmt.Sprintf("scrolled %d", delta), nil
}
