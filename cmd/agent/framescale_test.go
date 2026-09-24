package main

import "testing"

// effectiveScale must mirror captureRaw's halve condition exactly: any
// divergence sends clicks to the wrong pixels.
func TestEffectiveScale(t *testing.T) {
	cases := []struct {
		in   float64
		want float64
	}{
		{0, 1},
		{1, 1},
		{2, 1},
		{-1, 1},
		{0.5, 0.5},
		{0.25, 0.25},
		{0.999, 0.999},
	}
	for _, c := range cases {
		if got := effectiveScale(c.in); got != c.want {
			t.Fatalf("effectiveScale(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
