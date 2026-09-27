package commands

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

// Crash-resume: a re-begin with a matching manifest keeps received
// chunks (sidecar); a mismatched manifest starts fresh.
func TestFileUlResume(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.bin")
	if _, err := StartFileUl(p, 100, "sha1", 2); err != nil {
		t.Fatal(err)
	}
	chunk := base64.StdEncoding.EncodeToString([]byte("chunk0"))
	if _, err := WriteFileUlChunk(0, chunk, 50); err != nil {
		t.Fatal(err)
	}
	// Simulate a restart: drop memory state, keep disk.
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
	res, err := StartFileUl(p, 100, "sha1", 2)
	if err != nil {
		t.Fatalf("resume refused: %v", err)
	}
	if !strings.Contains(res, "resumed 1/2") {
		t.Fatalf("resume message = %q, want resumed 1/2", res)
	}
	// Mismatched manifest must NOT resume.
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
	res, err = StartFileUl(p, 200, "sha2", 4)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res, "resumed") {
		t.Fatalf("mismatched manifest resumed: %q", res)
	}
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
}

func TestCompressRanges(t *testing.T) {
	if got := compressRanges(map[int]bool{}, 10); got != "none" {
		t.Fatalf("empty = %q", got)
	}
	have := map[int]bool{0: true, 1: true, 2: true, 5: true, 7: true, 8: true, 9: true}
	if got := compressRanges(have, 10); got != "0-2,5,7-9" {
		t.Fatalf("got %q", got)
	}
}

func TestUploadStatus(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.bin")
	if out, _ := uploadStatus(""); out != "" {
		t.Fatal("empty path should error")
	}
	if out, err := uploadStatus(p); err != nil || !strings.HasPrefix(out, "upload unknown ") {
		t.Fatalf("no session = %q,%v", out, err)
	}
	if _, err := StartFileUl(p, 100, "", 2); err != nil {
		t.Fatal(err)
	}
	out, err := uploadStatus(p)
	if err != nil || out != "upload have 2 none "+p {
		t.Fatalf("fresh session = %q,%v", out, err)
	}
	chunk := base64.StdEncoding.EncodeToString([]byte("chunk0"))
	if _, err := WriteFileUlChunk(0, chunk, 50); err != nil {
		t.Fatal(err)
	}
	out, err = uploadStatus(p)
	if err != nil || out != "upload have 2 0 "+p {
		t.Fatalf("partial session = %q,%v", out, err)
	}
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
}

func TestStartFileUlAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "done.bin")
	content := []byte("already-here-bytes")
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(content)
	sha := hex.EncodeToString(h[:])
	res, err := StartFileUl(p, int64(len(content)), sha, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res, "upload complete: ") {
		t.Fatalf("already-present not detected: %q", res)
	}
	fileUlMu.Lock()
	fileUlState = nil
	fileUlMu.Unlock()
	_ = os.Remove(p + ".part")
	_ = os.Remove(p + ".part.json")
}
