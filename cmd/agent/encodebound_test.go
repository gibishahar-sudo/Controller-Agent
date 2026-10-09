package main

import (
	"image"
	"image/color"
	"math/rand"
	"testing"
)

// noiseImage builds a deterministic hard-to-compress frame.
func noiseImage(w, h int) *image.RGBA {
	rng := rand.New(rand.NewSource(1))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = byte(rng.Intn(256))
	}
	return img
}

// flatImage builds a deterministic easy frame.
func flatImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{uint8(x % 256), uint8(y % 256), 128, 255})
		}
	}
	return img
}

// encodeBounded must fit easy frames immediately, shrink hard frames
// toward the cap, and never go below the floor (v1.47.0: 150KB keyframes
// wedged thin relay links behind single frames).
func TestEncodeBounded(t *testing.T) {
	easy := flatImage(960, 540)
	d, q := encodeBounded(easy, 70, 20, keyframeByteCap)
	if d == nil || q != 70 {
		t.Fatalf("easy frame must pass through at q70: q=%d nil=%v", q, d == nil)
	}
	if len(d) > keyframeByteCap {
		t.Fatalf("easy frame exceeds cap: %d", len(d))
	}
	hard := noiseImage(960, 540)
	full, _, _ := encodeImage(hard, 70)
	d, q = encodeBounded(hard, 70, 20, keyframeByteCap)
	if d == nil {
		t.Fatal("hard frame must still return bytes")
	}
	if q >= 70 {
		t.Fatalf("hard frame must step quality down: q=%d", q)
	}
	if q < 20 {
		t.Fatalf("floor violated: q=%d", q)
	}
	if len(d) >= len(full) {
		t.Fatalf("bounded (%d) must beat unbounded (%d)", len(d), len(full))
	}
	if keyframeByteCap != 64*1024 {
		t.Fatalf("cap drifted: %d", keyframeByteCap)
	}
}
