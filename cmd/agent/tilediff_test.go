package main

import (
	"hash/fnv"
	"testing"
)

// diffTiles is the hot path of tile streaming: one hash pass per frame
// against cached prev-hashes (the old diffRects hashed both sides).
func TestDiffTilesIdentical(t *testing.T) {
	w, h, stride := 256, 128, 256*4
	cur := make([]byte, stride*h)
	for i := range cur {
		cur[i] = byte(i * 31)
	}
	// First sighting (no prev hashes): everything changed (defense path).
	ch, ratio, fresh := diffTiles(cur, stride, w, h, nil)
	if len(ch) != 2 { // 2x1 tiles of 128px over 256x128
		t.Fatalf("nil prev: got %d changed, want 2", len(ch))
	}
	if ratio <= 0.9 {
		t.Fatalf("nil prev: ratio %v, want ~1", ratio)
	}
	if len(fresh) != 2 {
		t.Fatalf("fresh hashes: got %d, want 2", len(fresh))
	}
	// Second frame, same pixels, cached hashes: nothing changed.
	ch2, ratio2, fresh2 := diffTiles(cur, stride, w, h, fresh)
	if len(ch2) != 0 || ratio2 != 0 {
		t.Fatalf("identical: got %d changed ratio %v, want 0/0", len(ch2), ratio2)
	}
	if len(fresh2) != 2 {
		t.Fatalf("fresh2: got %d, want 2", len(fresh2))
	}
	for i := range fresh {
		if fresh[i] != fresh2[i] {
			t.Fatalf("hash drift at %d for identical frames", i)
		}
	}
}

func TestDiffTilesOnePixel(t *testing.T) {
	w, h, stride := 256, 256, 256*4
	cur := make([]byte, stride*h)
	_, _, fresh := diffTiles(cur, stride, w, h, nil)
	cur[200*stride+100*4] ^= 0xFF // one pixel deep in tile (0,1)
	ch, _, _ := diffTiles(cur, stride, w, h, fresh)
	if len(ch) != 1 {
		t.Fatalf("one pixel: got %d changed, want 1", len(ch))
	}
	if ch[0] != [4]int{0, 128, 128, 128} {
		t.Fatalf("one pixel: rect %v, want tile (0,1)", ch[0])
	}
}

func TestDiffTilesShortPrev(t *testing.T) {
	w, h, stride := 128, 128, 128*4
	cur := make([]byte, stride*h)
	ch, _, _ := diffTiles(cur, stride, w, h, []uint64{1, 2}) // wrong length
	if len(ch) != 1 {
		t.Fatalf("short prev: got %d changed, want 1 (all)", len(ch))
	}
}

// hashTile must stay bit-identical to hash/fnv FNV-1a/64: cached hashes
// are compared across frames (and the inline rewrite must not drift).
func TestHashTileMatchesFNV(t *testing.T) {
	stride, h := 300*4, 200
	pix := make([]byte, stride*h)
	for i := range pix {
		pix[i] = byte(i*2654435761 + 97)
	}
	for _, tc := range [][4]int{{0, 0, 128, 128}, {128, 0, 128, 128}, {0, 128, 44, 72}, {256, 150, 44, 50}} {
		x, y, tw, th := tc[0], tc[1], tc[2], tc[3]
		hf := fnv.New64a()
		for row := 0; row < th; row++ {
			off := (y+row)*stride + x*4
			hf.Write(pix[off : off+tw*4])
		}
		if got, want := hashTile(pix, stride, x, y, tw, th), hf.Sum64(); got != want {
			t.Fatalf("tile %v: inline %x != fnv %x", tc, got, want)
		}
	}
}
