//go:build !windows

package main

import (
	"fmt"
	"image"
)

// captureLayered is Windows-only (GDI overlays); elsewhere the
// platform capturer stays the only path.
func captureLayered(rect image.Rectangle) (*image.RGBA, error) {
	return nil, fmt.Errorf("layered capture is windows-only")
}

// captureLayeredScaled is Windows-only (StretchBlt downscale); elsewhere
// the caller falls back to full-res + halveRGBA.
func captureLayeredScaled(rect image.Rectangle) (*image.RGBA, error) {
	return nil, fmt.Errorf("layered capture is windows-only")
}
