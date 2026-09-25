package controller

import (
	"fmt"
	"testing"
	"time"
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

// supersededRow evicts only stale, version-mismatched same-host rows.
func TestSupersededRow(t *testing.T) {
	now := time.Now()
	mk := func(id, host, ver string, ago time.Duration) (string, *AgentConn) {
		ac := &AgentConn{id: id, hostname: host, version: ver}
		ac.lastSeenMu.Lock()
		ac.lastSeen = now.Add(-ago)
		ac.lastSeenMu.Unlock()
		return id, ac
	}
	idOld, old := mk("agent-mqtt-H-1", "H", "1.45.8", 10*time.Minute)
	if !supersededRow(idOld, old, "agent-mqtt-H-2", "H", "1.45.9", now) {
		t.Fatal("stale old-version duplicate not evicted")
	}
	_, live := mk("agent-mqtt-H-3", "H", "1.45.8", 10*time.Second)
	if supersededRow("agent-mqtt-H-3", live, "agent-mqtt-H-2", "H", "1.45.9", now) {
		t.Fatal("fresh old-version row evicted (slow sibling handshake)")
	}
	_, same := mk("agent-mqtt-H-4", "H", "1.45.9", 10*time.Minute)
	if supersededRow("agent-mqtt-H-4", same, "agent-mqtt-H-2", "H", "1.45.9", now) {
		t.Fatal("stale same-version sibling evicted")
	}
	_, other := mk("agent-mqtt-X-1", "X", "1.45.8", 10*time.Minute)
	if supersededRow("agent-mqtt-X-1", other, "agent-mqtt-H-2", "H", "1.45.9", now) {
		t.Fatal("different-host row evicted")
	}
	_, self := mk("agent-mqtt-H-2", "H", "1.45.9", 10*time.Minute)
	if supersededRow("agent-mqtt-H-2", self, "agent-mqtt-H-2", "H", "1.45.9", now) {
		t.Fatal("confirmed row evicted itself")
	}
	_, unk := mk("agent-mqtt-H-5", "H", "", 10*time.Minute)
	if !supersededRow("agent-mqtt-H-5", unk, "agent-mqtt-H-2", "H", "1.45.9", now) {
		t.Fatal("stale unknown-version row not evicted")
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

// E2E keys are per agent instance (agent-mqtt-host-pid), not per hostname,
// so duplicate same-hostname agents never flap each other's channel.
func TestE2EKeysPerInstance(t *testing.T) {
	s := &Server{e2eKeys: map[string][32]byte{}}
	var k1, k2 [32]byte
	k1[0], k2[0] = 1, 2
	a := "agent-mqtt-yigel-111"
	b := "agent-mqtt-yigel-222"
	s.e2eSet(a, k1)
	s.e2eSet(b, k2)
	if got, ok := s.e2eGet(a); !ok || got != k1 {
		t.Fatal("instance A key not isolated")
	}
	if got, ok := s.e2eGet(b); !ok || got != k2 {
		t.Fatal("instance B key not isolated")
	}
	if !s.e2eHas(a) || !s.e2eHas(b) {
		t.Fatal("e2eHas should be true for both instances")
	}
	if s.e2eHas("agent-mqtt-yigel-333") {
		t.Fatal("e2eHas should be false for unknown instance")
	}
	if _, ok := s.e2eGet("yigel"); ok {
		t.Fatal("bare hostname must not resolve a key (prevents cross-instance flap)")
	}
}

// resubscribeMQTT with no buses attached must be a silent no-op, never a
// panic: the 60s ticker fires from the first loop pass, before any dial.
func TestResubscribeNilBuses(t *testing.T) {
	s := &Server{}
	s.resubscribeMQTT()
}
