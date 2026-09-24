package commands

import (
	"testing"
)

// parseAudioBlock accepts exactly one v2 block and splits seq/flags/data.
func TestParseAudioBlock(t *testing.T) {
	raw := make([]byte, audioStreamChunk)
	raw[0], raw[1], raw[2], raw[3] = 0x78, 0x56, 0x34, 0x12
	raw[4] = 1
	for i := 5; i < len(raw); i++ {
		raw[i] = byte(i)
	}
	blk, ok := parseAudioBlock(raw)
	if !ok {
		t.Fatal("valid 281B block rejected")
	}
	if blk.seq != 0x12345678 {
		t.Fatalf("seq = %#x, want 0x12345678", blk.seq)
	}
	if !blk.key {
		t.Fatal("key flag lost")
	}
	if len(blk.data) != audioBlockData {
		t.Fatalf("data len = %d, want %d", len(blk.data), audioBlockData)
	}
	// Mutating the returned slice must not alias the input.
	blk.data[0] ^= 0xFF
	if raw[5] == blk.data[0] {
		t.Fatal("data aliases input buffer")
	}
	for _, bad := range [][]byte{nil, {}, make([]byte, 100), make([]byte, 552), make([]byte, 282)} {
		if _, ok := parseAudioBlock(bad); ok {
			t.Fatalf("len %d accepted, want reject", len(bad))
		}
	}
}

// encodeAudioFrame lays out ver + seq LE + flags + payload; parse inverts it.
func TestAudioFrameRoundTrip(t *testing.T) {
	data := make([]byte, audioBlockData)
	for i := range data {
		data[i] = byte(i * 7)
	}
	f := encodeAudioFrame(0xAABBCCDD, true, data)
	if len(f) != 6+audioBlockData {
		t.Fatalf("frame len = %d", len(f))
	}
	if f[0] != 0x02 {
		t.Fatalf("ver = %#x, want 0x02", f[0])
	}
	// Reframe as a capture block and parse back.
	raw := make([]byte, audioStreamChunk)
	copy(raw, f[1:5])
	raw[4] = f[5]
	copy(raw[5:], f[6:])
	blk, ok := parseAudioBlock(raw)
	if !ok {
		t.Fatal("round-trip block rejected")
	}
	if blk.seq != 0xAABBCCDD || !blk.key {
		t.Fatalf("round trip = seq %#x key %v", blk.seq, blk.key)
	}
	for i := range data {
		if blk.data[i] != data[i] {
			t.Fatalf("payload byte %d differs", i)
		}
	}
}

// publishAudioBlocks seals plaintext frames plain (0x02) and encrypted
// batches as one 0x03 blob. Seal path needs a fake bus; instead verify
// frame layout properties the controller relies on: fixed 282B stride.
func TestAudioFrameStride(t *testing.T) {
	if 6+audioBlockData != 282 {
		t.Fatalf("frame stride = %d, controller splits on 282", 6+audioBlockData)
	}
}
