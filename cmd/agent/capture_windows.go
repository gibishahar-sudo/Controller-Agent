//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"image"
	"unsafe"

	"golang.org/x/sys/windows"
)

// captureLayered grabs rect via BitBlt SRCCOPY|CAPTUREBLT so layered
// windows and most hardware video overlays render instead of black.
// kbinani/screenshot uses SRCCOPY only, which misses exactly those —
// a playing video then captures as a black rectangle (tile-diff finds
// nothing, frames arrive ~1KB, perceived fps collapses while the
// nominal rate looks fine). Pure Win32, no new dependencies.
// Negative origins (multi-monitor left/above primary) are fine: the
// source coords truncate to 32-bit at the ABI like GDI expects.
func captureLayered(rect image.Rectangle) (*image.RGBA, error) {
	w, h := rect.Dx(), rect.Dy()
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("empty rect")
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	gdi32 := windows.NewLazySystemDLL("gdi32.dll")
	getDC := user32.NewProc("GetDC")
	releaseDC := user32.NewProc("ReleaseDC")
	createCompatDC := gdi32.NewProc("CreateCompatibleDC")
	createCompatBmp := gdi32.NewProc("CreateCompatibleBitmap")
	selectObj := gdi32.NewProc("SelectObject")
	bitBlt := gdi32.NewProc("BitBlt")
	deleteObj := gdi32.NewProc("DeleteObject")
	deleteDC := gdi32.NewProc("DeleteDC")
	getDIBits := gdi32.NewProc("GetDIBits")

	const srccopy = 0x00CC0020
	const captureblt = 0x40000000

	hdcScr, _, _ := getDC.Call(0)
	if hdcScr == 0 {
		return nil, fmt.Errorf("GetDC failed")
	}
	defer releaseDC.Call(0, hdcScr)
	hdcMem, _, _ := createCompatDC.Call(hdcScr)
	if hdcMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer deleteDC.Call(hdcMem)
	hbmp, _, _ := createCompatBmp.Call(hdcScr, uintptr(w), uintptr(h))
	if hbmp == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	oldBmp, _, _ := selectObj.Call(hdcMem, hbmp)
	defer deleteObj.Call(hbmp)
	defer selectObj.Call(hdcMem, oldBmp)
	r, _, _ := bitBlt.Call(hdcMem, 0, 0, uintptr(w), uintptr(h), hdcScr,
		uintptr(int32(rect.Min.X)), uintptr(int32(rect.Min.Y)), srccopy|captureblt)
	if r == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}
	// BITMAPINFOHEADER: 40 bytes, 32bpp top-down (negative height).
	var bi [40]byte
	binary.LittleEndian.PutUint32(bi[0:], 40)
	binary.LittleEndian.PutUint32(bi[4:], uint32(int32(w)))
	binary.LittleEndian.PutUint32(bi[8:], uint32(int32(-h)))
	binary.LittleEndian.PutUint16(bi[12:], 1)
	binary.LittleEndian.PutUint16(bi[14:], 32)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	ret, _, _ := getDIBits.Call(hdcMem, hbmp, 0, uintptr(h),
		uintptr(unsafe.Pointer(&img.Pix[0])), uintptr(unsafe.Pointer(&bi[0])), 0)
	if ret == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}
	// GDI delivers BGRA; image.RGBA wants RGBA.
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+2] = img.Pix[i+2], img.Pix[i]
	}
	return img, nil
}

// captureLayeredScaled is captureLayered with the downscale folded into
// the blit: StretchBlt copies screen -> half-size bitmap in GDI, so the
// full-res GetDIBits transfer, the full-frame BGRA swap, and the Go
// halveRGBA box-average pass all disappear (~15-30ms/frame saved). Any
// error returns normally and the caller falls back to full-res + halve.
// COLORONCOLOR (not HALFTONE): pixel-dropping is faster and streaming
// frames don't need print-grade smoothing.
func captureLayeredScaled(rect image.Rectangle) (*image.RGBA, error) {
	w, h := rect.Dx(), rect.Dy()
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("empty rect")
	}
	dw, dh := w/2, h/2
	if dw < 1 {
		dw = 1
	}
	if dh < 1 {
		dh = 1
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	gdi32 := windows.NewLazySystemDLL("gdi32.dll")
	getDC := user32.NewProc("GetDC")
	releaseDC := user32.NewProc("ReleaseDC")
	createCompatDC := gdi32.NewProc("CreateCompatibleDC")
	createCompatBmp := gdi32.NewProc("CreateCompatibleBitmap")
	selectObj := gdi32.NewProc("SelectObject")
	setStretchMode := gdi32.NewProc("SetStretchBltMode")
	stretchBlt := gdi32.NewProc("StretchBlt")
	deleteObj := gdi32.NewProc("DeleteObject")
	deleteDC := gdi32.NewProc("DeleteDC")
	getDIBits := gdi32.NewProc("GetDIBits")

	const srccopy = 0x00CC0020
	const captureblt = 0x40000000
	const coloroncolor = 3

	hdcScr, _, _ := getDC.Call(0)
	if hdcScr == 0 {
		return nil, fmt.Errorf("GetDC failed")
	}
	defer releaseDC.Call(0, hdcScr)
	hdcMem, _, _ := createCompatDC.Call(hdcScr)
	if hdcMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer deleteDC.Call(hdcMem)
	hbmp, _, _ := createCompatBmp.Call(hdcScr, uintptr(dw), uintptr(dh))
	if hbmp == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	oldBmp, _, _ := selectObj.Call(hdcMem, hbmp)
	defer deleteObj.Call(hbmp)
	defer selectObj.Call(hdcMem, oldBmp)
	setStretchMode.Call(hdcMem, coloroncolor)
	r, _, _ := stretchBlt.Call(hdcMem, 0, 0, uintptr(dw), uintptr(dh), hdcScr,
		uintptr(int32(rect.Min.X)), uintptr(int32(rect.Min.Y)), uintptr(w), uintptr(h), srccopy|captureblt)
	if r == 0 {
		return nil, fmt.Errorf("StretchBlt failed")
	}
	var bi [40]byte
	binary.LittleEndian.PutUint32(bi[0:], 40)
	binary.LittleEndian.PutUint32(bi[4:], uint32(int32(dw)))
	binary.LittleEndian.PutUint32(bi[8:], uint32(int32(-dh)))
	binary.LittleEndian.PutUint16(bi[12:], 1)
	binary.LittleEndian.PutUint16(bi[14:], 32)
	img := image.NewRGBA(image.Rect(0, 0, dw, dh))
	ret, _, _ := getDIBits.Call(hdcMem, hbmp, 0, uintptr(dh),
		uintptr(unsafe.Pointer(&img.Pix[0])), uintptr(unsafe.Pointer(&bi[0])), 0)
	if ret == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+2] = img.Pix[i+2], img.Pix[i]
	}
	return img, nil
}
