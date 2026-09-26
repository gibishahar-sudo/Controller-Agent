package commands

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 1GB transfers must be accepted; anything above refused up front.
func TestFileXferOneGBCap(t *testing.T) {
	if MaxFileXfer != 1<<30 {
		t.Fatalf("MaxFileXfer = %d, want 1GB", MaxFileXfer)
	}
	dir := t.TempDir()
	if _, err := StartFileUl(filepath.Join(dir, "big.bin"), 1<<30, "", 8192); err != nil {
		t.Fatalf("1GB upload refused: %v", err)
	}
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
	if _, err := StartFileUl(filepath.Join(dir, "big.bin"), (1<<30)+1, "", 8193); err == nil {
		t.Fatal("over-1GB upload accepted")
	}
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
}

// Expiry is activity-based: a slow-but-moving session survives even if
// it started hours ago; an idle one is reaped.
func TestFileUlSlidingExpiry(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "u.bin")
	if _, err := StartFileUl(p, 100, "", 2); err != nil {
		t.Fatal(err)
	}
	fileUlMu.Lock()
	st := fileUlState
	st.started = time.Now().Add(-3 * time.Hour) // ancient birth...
	st.lastChunk = time.Now()                  // ...but fresh activity
	fileUlMu.Unlock()
	chunk := base64.StdEncoding.EncodeToString([]byte("chunk0"))
	if _, err := WriteFileUlChunk(0, chunk, 50); err != nil {
		t.Fatalf("active session expired: %v", err)
	}
	fileUlMu.Lock()
	st = fileUlState
	st.lastChunk = time.Now().Add(-3 * time.Hour) // now truly idle
	fileUlMu.Unlock()
	if _, err := WriteFileUlChunk(1, chunk, 50); err == nil {
		t.Fatal("idle session should expire")
	}
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
}

// Manifest refuses over-cap downloads before hashing anything.
func TestFileDlManifestCap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1<<30 + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := FileDlManifest(p, 512*1024); err == nil {
		t.Fatal("over-1GB download manifest accepted")
	}
}
