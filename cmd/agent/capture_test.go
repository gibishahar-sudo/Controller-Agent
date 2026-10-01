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
		if _, err := captureLayered(r); err == nil {
			t.Fatalf("captureLayered(%v) must error", r)
		}
	}
}
