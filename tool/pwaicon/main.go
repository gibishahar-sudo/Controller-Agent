// Command pwaicon generates the PWA icons for the controller console
// (stdlib only, no external assets): dark tile + green status ring,
// at 192/512 plus a full-bleed maskable 512. Run from the repo root:
//
//	go run ./tool/pwaicon
//
// Output lands in internal/ui/frontend/icons/ (embedded into the build).
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

var (
	bgTile  = color.RGBA{0x11, 0x16, 0x1f, 0xff}
	bgBleed = color.RGBA{0x0b, 0x0e, 0x14, 0xff}
	green   = color.RGBA{0x7e, 0xe7, 0x87, 0xff}
	clear   = color.RGBA{0, 0, 0, 0}
)

func fillCircle(img *image.RGBA, cx, cy float64, r float64, c color.Color) {
	for y := int(cy - r - 1); y <= int(cy+r+1); y++ {
		for x := int(cx - r - 1); x <= int(cx+r+1); x++ {
			if math.Hypot(float64(x)-cx, float64(y)-cy) <= r {
				img.Set(x, y, c)
			}
		}
	}
}

func ring(img *image.RGBA, cx, cy, r, w float64, c color.Color) {
	for y := int(cy - r - w - 1); y <= int(cy+r+w+1); y++ {
		for x := int(cx - r - w - 1); x <= int(cx+r+w+1); x++ {
			d := math.Hypot(float64(x)-cx, float64(y)-cy)
			if math.Abs(d-r) <= w/2 {
				img.Set(x, y, c)
			}
		}
	}
}

func roundedTile(img *image.RGBA, rad float64) {
	n := img.Bounds().Dx()
	mask := image.NewRGBA(img.Bounds())
	draw.Draw(mask, mask.Bounds(), &image.Uniform{clear}, image.Point{}, draw.Src)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			in := true
			dx := math.Min(float64(x), float64(n-1-x))
			dy := math.Min(float64(y), float64(n-1-y))
			if dx < rad && dy < rad && math.Hypot(rad-dx, rad-dy) > rad {
				in = false
			}
			if in {
				mask.Set(x, y, color.Opaque)
			}
		}
	}
	out := image.NewRGBA(img.Bounds())
	draw.DrawMask(out, out.Bounds(), img, image.Point{}, mask, image.Point{}, draw.Over)
	copy(img.Pix, out.Pix)
}

// glyph draws the status ring + dot centered in a size×size box at (ox,oy).
func glyph(img *image.RGBA, ox, oy, size float64) {
	cx, cy := ox+size/2, oy+size/2
	ring(img, cx, cy, size*0.30, size*0.055, green)
	fillCircle(img, cx, cy, size*0.11, green)
	// Cardinal ticks (console crosshair feel).
	for _, a := range []float64{0, math.Pi / 2, math.Pi, 3 * math.Pi / 2} {
		tx, ty := cx+math.Cos(a)*size*0.42, cy+math.Sin(a)*size*0.42
		fillCircle(img, tx, ty, size*0.035, green)
	}
}

func save(path string, img *image.RGBA) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Println("CREATE FAIL:", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fmt.Println("ENCODE FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", path)
}

func main() {
	dir := filepath.Join("internal", "ui", "frontend", "icons")
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Println("MKDIR FAIL:", err)
		os.Exit(1)
	}
	// Regular icons: dark tile with rounded transparent corners.
	for _, n := range []int{192, 512} {
		img := image.NewRGBA(image.Rect(0, 0, n, n))
		draw.Draw(img, img.Bounds(), &image.Uniform{bgTile}, image.Point{}, draw.Src)
		roundedTile(img, float64(n)*0.22)
		s := float64(n)
		glyph(img, s*0.16, s*0.16, s*0.68)
		save(filepath.Join(dir, fmt.Sprintf("icon-%d.png", n)), img)
	}
	// Maskable: full-bleed dark, glyph at 68% centered (safe zone).
	n := 512
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	draw.Draw(img, img.Bounds(), &image.Uniform{bgBleed}, image.Point{}, draw.Src)
	s := float64(n)
	glyph(img, s*0.16, s*0.16, s*0.68)
	save(filepath.Join(dir, "maskable-512.png"), img)
}
