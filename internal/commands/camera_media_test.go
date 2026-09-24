//go:build windows

package commands

import (
	"image"
	"testing"
)

// scaleRGBABox downscales wide images preserving aspect, nil otherwise.
func TestScaleRGBABox(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 640, 480))
	for i := range src.Pix {
		src.Pix[i] = byte(i)
	}
	out := scaleRGBABox(src, 320)
	if out == nil {
		t.Fatal("wide image not scaled")
	}
	if w, h := out.Bounds().Dx(), out.Bounds().Dy(); w != 320 || h != 240 {
		t.Fatalf("scaled = %dx%d, want 320x240", w, h)
	}
	if scaleRGBABox(src, 640) != nil {
		t.Fatal("at-limit image should return nil (no work)")
	}
	if scaleRGBABox(src, 1280) != nil {
		t.Fatal("narrow image should return nil (no work)")
	}
	small := image.NewRGBA(image.Rect(0, 0, 100, 100))
	if scaleRGBABox(small, 320) != nil {
		t.Fatal("small image should return nil")
	}
	if scaleRGBABox(image.NewNRGBA(image.Rect(0, 0, 640, 480)), 320) != nil {
		t.Fatal("non-RGBA should return nil")
	}
}

// scaleRGBABox averages: a solid block stays solid.
func TestScaleRGBABoxSolid(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for i := 0; i < len(src.Pix); i += 4 {
		src.Pix[i], src.Pix[i+1], src.Pix[i+2], src.Pix[i+3] = 200, 100, 50, 255
	}
	out := scaleRGBABox(src, 32)
	if out == nil {
		t.Fatal("not scaled")
	}
	rgba := out.(*image.RGBA)
	for i := 0; i < len(rgba.Pix); i += 4 {
		if rgba.Pix[i] != 200 || rgba.Pix[i+1] != 100 || rgba.Pix[i+2] != 50 || rgba.Pix[i+3] != 255 {
			t.Fatalf("pixel %d = %v, want solid", i/4, rgba.Pix[i:i+4])
		}
	}
}
