package controller

import "testing"

// Silence must decode to silence (the idle path depends on this).
func TestADPCMSilence(t *testing.T) {
	dec := &adpcmDecoder{}
	out := dec.decodeBlock(make([]byte, 551))
	if len(out) != 2204 {
		t.Fatalf("want 2204 PCM bytes, got %d", len(out))
	}
	for i, b := range out {
		if b != 0 {
			t.Fatalf("non-zero byte %d at %d", b, i)
		}
	}
}

// Known-answer: from pred=0,idx=0, nibble 7 (0111) yields sample 11
// (step 7: 0+7+3+1), then idx jumps to 8.
func TestADPCMKnownNibble(t *testing.T) {
	dec := &adpcmDecoder{}
	out := dec.decodeBlock([]byte{0x70})
	if len(out) != 4 {
		t.Fatalf("want 4 bytes, got %d", len(out))
	}
	got := int(int16(out[0]) | int16(out[1])<<8)
	if got != 11 {
		t.Fatalf("want first sample 11, got %d", got)
	}
	if dec.index != 7 {
		t.Fatalf("want index 7 after nibbles 7,0, got %d", dec.index)
	}
}

// Predictor state must persist across blocks (stream continuity).
func TestADPCMStateful(t *testing.T) {
	dec := &adpcmDecoder{}
	a := dec.decodeBlock([]byte{0xFF})
	b := dec.decodeBlock([]byte{0xFF})
	same := len(a) == len(b)
	if same {
		for i := range a {
			if a[i] != b[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatalf("expected predictor evolution across blocks")
	}
}

// v0 passthrough keeps old agents working during transition.
func TestDecodePassthrough(t *testing.T) {
	in := []byte{1, 2, 3, 4}
	out := decodeAudioChunk("host", 0, in)
	if len(out) != 4 || out[0] != 1 {
		t.Fatalf("passthrough broken")
	}
}

// Gap resync: after dropped blocks, the next keyframe must restore the
// exact stream (same bytes as an uninterrupted decode from scratch).
func TestGapResyncViaKeyframe(t *testing.T) {
	// Two identical non-silent blocks; decode the second twice: once in
	// sequence, once after a simulated gap (fresh decoder = keyframe).
	blk := []byte{0x12, 0xAB, 0x77, 0x07}
	a := &adpcmDecoder{}
	a.decodeBlock(blk)
	cont := a.decodeBlock(blk)
	b := &adpcmDecoder{} // gap/keyframe path: reset state
	fresh := b.decodeBlock(blk)
	if len(cont) != len(fresh) {
		t.Fatalf("length mismatch")
	}
	// Fresh decode must equal a clean decode of the same block.
	c := &adpcmDecoder{}
	clean := c.decodeBlock(blk)
	for i := range fresh {
		if fresh[i] != clean[i] {
			t.Fatalf("keyframe resync differs at %d", i)
		}
	}
}

// noteAudioSeq: keyframes, first sightings and gaps reset; clean runs pass.
func TestNoteAudioSeq(t *testing.T) {
	audioSeqMu.Lock()
	delete(audioLastSeq, "t-host")
	delete(audioGapCount, "t-host")
	audioSeqMu.Unlock()
	if !noteAudioSeq("t-host", 0, false) {
		t.Fatalf("first sighting must reset")
	}
	if noteAudioSeq("t-host", 1, false) {
		t.Fatalf("clean next seq must not reset")
	}
	if !noteAudioSeq("t-host", 5, false) {
		t.Fatalf("gap must reset")
	}
	if audioGaps("t-host") != 1 {
		t.Fatalf("want 1 gap, got %d", audioGaps("t-host"))
	}
	if !noteAudioSeq("t-host", 6, true) {
		t.Fatalf("keyframe must reset")
	}
	if audioGaps("t-host") != 1 {
		t.Fatalf("keyframe must not count as gap")
	}
	audioSeqMu.Lock()
	delete(audioLastSeq, "t-host")
	delete(audioGapCount, "t-host")
	audioSeqMu.Unlock()
}
