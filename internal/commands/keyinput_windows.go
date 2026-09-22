//go:build windows

package commands

// Native keyboard injection via Win32 SendInput (stdlib syscall only, no
// cgo, no new dependencies). One syscall types a whole string (~1ms);
// the legacy path spawns a PowerShell per keystroke (~300-1000ms each).
// sendText/keyPress try native first and fall back to PowerShell on error.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"
)

var (
	procSendInput     = modUser32.NewProc("SendInput")
	procMapVirtualKey = modUser32.NewProc("MapVirtualKeyW")
	procVkKeyScan     = modUser32.NewProc("VkKeyScanW")
)

const (
	winInputKeyboard   = 1
	keyeventfExtended  = 0x0001
	keyeventfKeyup     = 0x0002
	keyeventfUnicode   = 0x0004
	keyeventfScancode  = 0x0008
	mapvkVkToVsc       = 0
	vkShift            = 0x10
	vkControl          = 0x11
	vkMenu             = 0x12 // Alt
)

// winInput is Win32 INPUT (40 bytes): DWORD type + 4 pad + 32-byte union.
// KEYBDINPUT occupies the first 20 union bytes (vk, scan, flags, time,
// extraInfo); the rest is zero padding to MOUSEINPUT size.
type winInput struct {
	Type uint32
	_    uint32
	U    [32]byte
}

func keybdInput(vk, scan uint16, flags uint32) winInput {
	var u [32]byte
	binary.LittleEndian.PutUint16(u[0:2], vk)
	binary.LittleEndian.PutUint16(u[2:4], scan)
	binary.LittleEndian.PutUint32(u[4:8], flags)
	return winInput{Type: winInputKeyboard, U: u}
}

func doSendInput(in []winInput) error {
	if len(in) == 0 {
		return nil
	}
	r1, _, _ := procSendInput.Call(
		uintptr(len(in)),
		uintptr(unsafe.Pointer(&in[0])),
		unsafe.Sizeof(in[0]),
	)
	if r1 != uintptr(len(in)) {
		return fmt.Errorf("SendInput accepted %d/%d", r1, len(in))
	}
	return nil
}

func vkDownUp(vk uint16, extended bool) []winInput {
	scan := uint16(0)
	if r1, _, _ := procMapVirtualKey.Call(uintptr(vk), mapvkVkToVsc); r1 != 0 {
		scan = uint16(r1)
	}
	flags := uint32(keyeventfScancode)
	if extended {
		flags |= keyeventfExtended
	}
	return []winInput{keybdInput(vk, scan, flags), keybdInput(vk, scan, flags|keyeventfKeyup)}
}

// sendTextNative types a whole string in one SendInput call (UTF-16 units,
// so every language/layout works). \n and \t map to Return/Tab.
func sendTextNative(t string) error {
	if strings.TrimSpace(t) == "" {
		return fmt.Errorf("empty")
	}
	var in []winInput
	flush := func(u [32]byte) {
		in = append(in, winInput{Type: winInputKeyboard, U: u})
		u[4] |= keyeventfKeyup
		in = append(in, winInput{Type: winInputKeyboard, U: u})
	}
	for _, u16 := range utf16.Encode([]rune(t)) {
		if u16 == '\n' {
			in = append(in, vkDownUp(0x0D, false)...) // Return
			continue
		}
		if u16 == '\r' {
			continue
		}
		if u16 == '\t' {
			in = append(in, vkDownUp(0x09, false)...) // Tab
			continue
		}
		var u [32]byte
		binary.LittleEndian.PutUint16(u[2:4], u16)
		binary.LittleEndian.PutUint32(u[4:8], keyeventfUnicode)
		flush(u)
	}
	return doSendInput(in)
}

// specialVK maps {TOKEN} names (upper-cased, braces stripped) to virtual
// keys. extended marks keys needing KEYEVENTF_EXTENDEDKEY. PRTSC is
// deliberately absent (SendInput needs a scancode quirk there) so it falls
// back to the PowerShell path.
var specialVK = map[string]struct {
	vk       uint16
	extended bool
}{
	"ENTER": {0x0D, false}, "TAB": {0x09, false}, "ESC": {0x1B, false}, "ESCAPE": {0x1B, false},
	"BACKSPACE": {0x08, false}, "BACK": {0x08, false}, "DELETE": {0x2E, true}, "DEL": {0x2E, true},
	"HOME": {0x24, true}, "END": {0x23, true}, "PGUP": {0x21, true}, "PRIOR": {0x21, true},
	"PGDN": {0x22, true}, "NEXT": {0x22, true}, "INSERT": {0x2D, true}, "INS": {0x2D, true},
	"LEFT": {0x25, true}, "UP": {0x26, true}, "RIGHT": {0x27, true}, "DOWN": {0x28, true},
	"CAPSLOCK": {0x14, false}, "CAPITAL": {0x14, false},
	"F1": {0x70, false}, "F2": {0x71, false}, "F3": {0x72, false}, "F4": {0x73, false},
	"F5": {0x74, false}, "F6": {0x75, false}, "F7": {0x76, false}, "F8": {0x77, false},
	"F9": {0x78, false}, "F10": {0x79, false}, "F11": {0x7A, false}, "F12": {0x7B, false},
}

// parseKeyPress compiles "key-press" bodies (^ % + modifiers, {TOKEN} or a
// single char) into SendInput events. Pure: unit-tested.
func parseKeyPress(key string) ([]winInput, error) {
	var mods []uint16
	rest := key
	for len(rest) > 0 && (rest[0] == '^' || rest[0] == '%' || rest[0] == '+') {
		switch rest[0] {
		case '^':
			mods = append(mods, vkControl)
		case '%':
			mods = append(mods, vkMenu)
		case '+':
			mods = append(mods, vkShift)
		}
		rest = rest[1:]
	}
	var main []winInput
	if strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") && len(rest) >= 2 {
		token := strings.ToUpper(rest[1 : len(rest)-1])
		sp, ok := specialVK[token]
		if !ok {
			return nil, fmt.Errorf("unknown key token %s", rest)
		}
		main = vkDownUp(sp.vk, sp.extended)
	} else if rs := []rune(rest); len(rs) == 1 {
		r := rs[0]
		var vk uint16
		needShift := false
		switch {
		case r >= 'a' && r <= 'z':
			vk = uint16(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z':
			vk = uint16(r)
		case r >= '0' && r <= '9':
			vk = uint16(r)
		default:
			// Punctuation/other: VkKeyScan gives VK + shift state.
			s, _, _ := procVkKeyScan.Call(uintptr(r))
			if s == 0xFFFF {
				return nil, fmt.Errorf("no virtual key for %q", r)
			}
			vk = uint16(s & 0xFF)
			needShift = s&(0x100) != 0
		}
		main = vkDownUp(vk, false)
		if needShift {
			hasShift := false
			for _, m := range mods {
				if m == vkShift {
					hasShift = true
				}
			}
			if !hasShift {
				mods = append([]uint16{vkShift}, mods...)
			}
		}
	} else {
		return nil, fmt.Errorf("unrecognized key %q", key)
	}
	var out []winInput
	for _, m := range mods {
		out = append(out, vkDownUp(m, false)[:1]...) // downs only
	}
	out = append(out, main...)
	for i := len(mods) - 1; i >= 0; i-- {
		out = append(out, vkDownUp(mods[i], false)[1:]...) // ups, reverse order
	}
	return out, nil
}

// keyPressNative presses parsed keys (modifiers held across the main key).
func keyPressNative(key string) error {
	in, err := parseKeyPress(strings.TrimSpace(key))
	if err != nil {
		return err
	}
	return doSendInput(in)
}
