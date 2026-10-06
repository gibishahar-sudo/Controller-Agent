package main

import (
	"image"
	"testing"
)

// Empty rects must fail fast on every platform (the live path needs a
// display, which CI lacks — this pins the contract, not the pixels).
func TestCaptureLayeredEmptyRect(t *testing.T) {
	for _, r := range []image.Rectangle{
		image.Rect(0, 0, 0, 0),
		image.Rect(5, 5, 5, 10),
		image.Rect(2, 2, 2, 2),
	} {
		if _, err := captureLayered(r, true); err == nil {
			t.Fatalf("captureLayered(%v) must error", r)
		}
		if _, err := captureLayeredScaled(r); err == nil {
			t.Fatalf("captureLayeredScaled(%v) must error", r)
		}
	}
}

// halveBGRAsrc must box-average AND unswap channels: BGRA in, RGBA out.
func TestHalveBGRASwap(t *testing.T) {
	// 2x2 BGRA: B,G,R,A per pixel chosen so the average is unambiguous.
	src := []byte{
		10, 20, 30, 40, 50, 60, 70, 80,
		90, 100, 110, 120, 130, 140, 150, 160,
	}
	out := halveBGRAsrc(src, 8, 2, 2)
	if out.Bounds().Dx() != 1 || out.Bounds().Dy() != 1 {
		t.Fatalf("dims %v, want 1x1", out.Bounds())
	}
	// B avg=(10+50+90+130)/4=70 -> out[2]; G avg=80 -> out[1];
	// R avg=(30+70+110+150)/4=90 -> out[0]; A avg=100 -> out[3].
	want := []byte{90, 80, 70, 100}
	for i, w := range want {
		if out.Pix[i] != w {
			t.Fatalf("pix[%d]=%d want %d (pix=%v)", i, out.Pix[i], w, out.Pix)
		}
	}
}
