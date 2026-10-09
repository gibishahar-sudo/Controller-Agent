package main

import (
	"testing"
)

// adaptPushQuality is the thin-link lifeline (v1.46.94): slow cycles
// must reach the 25 floor (40 left 150KB frames = 10s+ each on relay),
// fast cycles must recover exactly to qHi, and the floor must hold.
func TestAdaptPushQuality(t *testing.T) {
	cases := []struct {
		q, qHi int
		ema    float64
		want   int
		step   bool
	}{
		{50, 50, 150, 40, true},   // slow: shed
		{40, 50, 150, 30, true},   // slow: keep shedding past old 40 floor
		{30, 50, 150, 25, true},   // slow: clamp at the floor, no overshoot
		{25, 50, 150, 25, false},  // slow at floor: hold
		{20, 50, 150, 20, false},  // slow below floor (legacy): hold, never climb here
		{25, 50, 20, 30, true},    // fast: recover
		{48, 50, 20, 50, true},    // fast: cap at qHi
		{50, 50, 20, 50, false},   // fast at qHi: hold
		{40, 50, 70, 40, false},   // mid: hold
		{40, 30, 20, 40, false},   // qHi below q (odd config): never exceed q... q<qHi false
	}
	for _, c := range cases {
		got, step := adaptPushQuality(c.q, c.qHi, c.ema)
		if got != c.want || step != c.step {
			t.Fatalf("adapt(%d,%d,%.0f) = (%d,%v) want (%d,%v)", c.q, c.qHi, c.ema, got, step, c.want, c.step)
		}
	}
	if pushMinQuality != 25 {
		t.Fatalf("floor drifted: %d", pushMinQuality)
	}
}
