package controller

import (
	"fmt"
	"testing"
)

// verOlderThan gates the 1.45 update-required flag.
func TestVerOlderThan(t *testing.T) {
	cases := []struct {
		v, min string
		want   bool
	}{
		{"1.44.1", "1.45.0", true},
		{"1.45.0", "1.45.0", false},
		{"1.45.1", "1.45.0", false},
		{"1.9.9", "1.45.0", true},
		{"2.0.0", "1.45.0", false},
		{"", "1.45.0", false},
		{"abc", "1.45.0", false},
		{"1.45", "1.45.0", true},
		{"1.45.0", "1.45", false},
	}
	for _, c := range cases {
		if got := verOlderThan(c.v, c.min); got != c.want {
			t.Fatalf("verOlderThan(%q, %q) = %v, want %v", c.v, c.min, got, c.want)
		}
	}
}

// haveRanges compresses to spans the agent's ParseRanges inverts.
func TestHaveRanges(t *testing.T) {
	if s := haveRanges(map[int]bool{}, 30); s != "" {
		t.Fatalf("empty = %q, want empty", s)
	}
	have := map[int]bool{0: true, 1: true, 2: true, 5: true, 7: true, 8: true, 29: true}
	if s := haveRanges(have, 30); s != "0-2,5,7-8,29" {
		t.Fatalf("spans = %q, want 0-2,5,7-8,29", s)
	}
	full := map[int]bool{}
	for i := 0; i < 10; i++ {
		full[i] = true
	}
	if s := haveRanges(full, 10); s != "0-9" {
		t.Fatalf("full = %q, want 0-9", s)
	}
}

// noteAudioSeq: first sighting + keyframes reset, continuity passes,
// any jump counts a gap exactly once.
func TestNoteAudioSeqGaps(t *testing.T) {
	host := "test-seq-host"
	audioSeqMu.Lock()
	delete(audioLastSeq, host)
	delete(audioGapCount, host)
	audioSeqMu.Unlock()
	if !noteAudioSeq(host, 100, false) {
		t.Fatal("first sighting must reset")
	}
	if noteAudioSeq(host, 101, false) {
		t.Fatal("continuous seq must not reset")
	}
	if !noteAudioSeq(host, 105, false) {
		t.Fatal("gap must reset")
	}
	if got := audioGaps(host); got != 1 {
		t.Fatalf("gaps = %d, want 1", got)
	}
	if !noteAudioSeq(host, 106, true) {
		t.Fatal("keyframe must reset")
	}
	if got := audioGaps(host); got != 1 {
		t.Fatalf("keyframe must not count a gap, gaps = %d", got)
	}
	audioSeqMu.Lock()
	delete(audioLastSeq, host)
	delete(audioGapCount, host)
	audioSeqMu.Unlock()
}

// assembleCamFrag completes split frames and ignores strays.
func TestAssembleCamFrag(t *testing.T) {
	s := &Server{}
	id := "agent-test-1"
	l0 := "CAMFRAG 99 0/2 QUJD"
	l1 := "CAMFRAG 99 1/2 REVG"
	if _, ok := s.assembleCamFrag(id, l0); ok {
		t.Fatal("incomplete assembly reported done")
	}
	url, ok := s.assembleCamFrag(id, l1)
	if !ok {
		t.Fatal("complete assembly not reported")
	}
	if url != "QUJDREVG" {
		t.Fatalf("assembled = %q, want QUJDREVG", url)
	}
	// A lone frag after completion starts a fresh (incomplete) assembly.
	if _, ok := s.assembleCamFrag(id, l1); ok {
		t.Fatal("lone post-completion frag reported done")
	}
	// Garbage never assembles.
	for _, bad := range []string{"", "CAMFRAG", "CAMFRAG 1 0/0 x", "CAMFRAG 1 5/2 x", "CAMFRAG 1 0/99 x", "hello"} {
		if _, ok := s.assembleCamFrag(id, bad); ok {
			t.Fatalf("%q assembled", bad)
		}
	}
	if !isCamFragLine("CAMFRAG 1 0/2 QUJD") {
		t.Fatal("valid frag line rejected")
	}
	if isCamFragLine("data:image/jpeg;base64,QUJD") {
		t.Fatal("data URL mistaken for frag")
	}
}

// Out-of-order frags still complete (QoS0 reordering).
func TestAssembleCamFragOrder(t *testing.T) {
	s := &Server{}
	id := "agent-test-2"
	mk := func(seq, total int) string { return fmt.Sprintf("CAMFRAG 7 %d/%d D%d", seq, total, seq) }
	if _, ok := s.assembleCamFrag(id, mk(2, 3)); ok {
		t.Fatal("1/3 reported done")
	}
	if _, ok := s.assembleCamFrag(id, mk(0, 3)); ok {
		t.Fatal("2/3 reported done")
	}
	url, ok := s.assembleCamFrag(id, mk(1, 3))
	if !ok || url != "D0D1D2" {
		t.Fatalf("assembled = %q, %v", url, ok)
	}
}
