package commands

import (
	"testing"
)

// rangesOf and ParseRanges are inverses across shapes: empty, single,
// contiguous, fragmented, and full coverage.
func TestRangesRoundTrip(t *testing.T) {
	cases := []map[int]bool{
		{},
		{0: true},
		{0: true, 1: true, 2: true},
		{0: true, 1: true, 2: true, 5: true, 7: true, 8: true, 9: true},
		{3: true, 29: true},
	}
	const total = 30
	for i, have := range cases {
		s := rangesOf(have, total)
		back := ParseRanges(s, total)
		if len(back) != len(have) {
			t.Fatalf("case %d: ranges %q round-trips to %d entries, want %d", i, s, len(back), len(have))
		}
		for k := range have {
			if !back[k] {
				t.Fatalf("case %d: ranges %q lost chunk %d", i, s, k)
			}
		}
	}
}

// Full coverage compresses to a single span.
func TestRangesFullSpan(t *testing.T) {
	have := map[int]bool{}
	for i := 0; i < 30; i++ {
		have[i] = true
	}
	if s := rangesOf(have, 30); s != "0-29" {
		t.Fatalf("full ranges = %q, want 0-29", s)
	}
}

// Out-of-range and garbage tokens are dropped, never trusted.
func TestParseRangesBounds(t *testing.T) {
	got := ParseRanges("0-29,30,99,-1,abc,5-3,,", 30)
	for k := range got {
		if k < 0 || k >= 30 {
			t.Fatalf("out-of-range chunk %d accepted", k)
		}
	}
	if len(got) != 30 {
		t.Fatalf("got %d entries, want 30", len(got))
	}
}

// Empty input is the fresh-accept case: no chunks, no error.
func TestParseRangesEmpty(t *testing.T) {
	if got := ParseRanges("", 30); len(got) != 0 {
		t.Fatalf("empty ranges = %d entries, want 0", len(got))
	}
}
