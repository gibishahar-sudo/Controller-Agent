package commands

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Chunked file transfer engine (both directions). Downloads stream straight
// off disk (no whole-file memory); uploads reassemble in a .part file and
// rename into place only after size+sha verify.

// MaxFileXfer caps single transfers (matches the update path's 256MB).
const MaxFileXfer = 256 << 20

// FileManifest describes a download source.
type FileManifest struct {
	Size  int64
	SHA   string
	Total int
}

// ZipDirToTemp packs a directory into a deterministic zip (sorted entries,
// fixed timestamps so re-zips are byte-identical and gap-fill resumes stay
// consistent). Returns the temp zip path; caller removes it.
func ZipDirToTemp(srcDir string) (string, error) {
	var files []string
	if err := filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(files)
	tmp, err := os.CreateTemp("", "rmmdl-*.zip")
	if err != nil {
		return "", err
	}
	zw := zip.NewWriter(tmp)
	for _, f := range files {
		rel, err := filepath.Rel(srcDir, f)
		if err != nil {
			continue
		}
		hdr := &zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate}
		hdr.SetModTime(time.Unix(0, 0))
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			continue
		}
		in, err := os.Open(f)
		if err != nil {
			continue
		}
		_, _ = io.Copy(w, in)
		in.Close()
	}
	_ = zw.Close()
	_ = tmp.Close()
	return tmp.Name(), nil
}

// ResolveDlSource maps a download request to a streamable file: plain files
// pass through, directories become a deterministic temp zip (caller deletes
// when cleanup is true).
func ResolveDlSource(path string) (realPath, displayName string, cleanup bool, err error) {
	if path == "" {
		return "", "", false, fmt.Errorf("path required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", "", false, err
	}
	if !st.IsDir() {
		return path, filepath.Base(path), false, nil
	}
	zp, err := ZipDirToTemp(path)
	if err != nil {
		return "", "", false, err
	}
	return zp, filepath.Base(path) + ".zip", true, nil
}

// FileDlManifest stats a download source and hashes it.
func FileDlManifest(path string, chunkRaw int) (*FileManifest, error) {
	if path == "" {
		return nil, fmt.Errorf("path required")
	}
	if chunkRaw <= 0 {
		chunkRaw = 512 * 1024
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("not a file: %s (request the folder to auto-zip)", path)
	}
	if st.Size() > MaxFileXfer {
		return nil, fmt.Errorf("file too large (%d bytes, cap %d)", st.Size(), MaxFileXfer)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	total := int((st.Size() + int64(chunkRaw) - 1) / int64(chunkRaw))
	if total < 1 {
		total = 1
	}
	return &FileManifest{Size: st.Size(), SHA: hex.EncodeToString(h.Sum(nil)), Total: total}, nil
}

// FileDlChunk reads one download chunk as base64.
func FileDlChunk(path string, seq, chunkRaw int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Seek(int64(seq)*int64(chunkRaw), 0); err != nil {
		return "", err
	}
	buf := make([]byte, chunkRaw)
	n, err := readFull(f, buf)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf[:n]), nil
}

func readFull(f *os.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil {
			break // EOF or error: return what we got
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("read past end of file")
	}
	return total, nil
}

var fileUlMu sync.Mutex
var fileUlState *fileUlSession

type fileUlSession struct {
	path    string
	size    int64
	sha     string
	total   int
	part    string
	have    map[int]bool
	started time.Time
}

// maxUlAge abandons uploads stalled this long (source deleted mid-upload,
// UI closed, agent restarted): the next begin starts clean instead of
// wedging on a zombie session.
const maxUlAge = 30 * time.Minute

// StartFileUl begins an upload: creates the .part file (parents included).
func StartFileUl(path string, size int64, sha string, total int) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	if total <= 0 || total > 100000 {
		return "", fmt.Errorf("bad upload manifest (total=%d)", total)
	}
	if size < 0 || size > MaxFileXfer {
		return "", fmt.Errorf("bad upload manifest (size=%d)", size)
	}
	fileUlMu.Lock()
	defer fileUlMu.Unlock()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	part := path + ".part"
	_ = os.Remove(part)
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", err
	}
	f.Close()
	fileUlState = &fileUlSession{path: path, size: size, sha: sha, total: total, part: part, have: map[int]bool{}, started: time.Now()}
	return fmt.Sprintf("upload %s accepted (%d bytes in %d chunks)", filepath.Base(path), size, total), nil
}

// WriteFileUlChunk stores one upload chunk at its offset; finalizes (verify
// + rename) when the set completes. Progress reported every 10%.
func WriteFileUlChunk(seq int, b64 string, chunkRaw int) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("chunk %d: bad base64", seq)
	}
	fileUlMu.Lock()
	st := fileUlState
	if st == nil {
		fileUlMu.Unlock()
		return "", fmt.Errorf("no upload in progress")
	}
	if time.Since(st.started) > maxUlAge {
		_ = os.Remove(st.part)
		fileUlState = nil
		fileUlMu.Unlock()
		return "", fmt.Errorf("upload session expired (stalled over 30min) — restart the upload")
	}
	if seq < 0 || seq >= st.total {
		fileUlMu.Unlock()
		return "", fmt.Errorf("chunk %d out of range", seq)
	}
	if chunkRaw <= 0 {
		chunkRaw = 512 * 1024
	}
	f, err := os.OpenFile(st.part, os.O_WRONLY, 0644)
	if err != nil {
		fileUlMu.Unlock()
		return "", err
	}
	_, err = f.WriteAt(raw, int64(seq)*int64(chunkRaw))
	f.Close()
	if err != nil {
		fileUlMu.Unlock()
		return "", err
	}
	st.have[seq] = true
	n := len(st.have)
	done := n == st.total
	fileUlMu.Unlock()
	if !done {
		if n%(st.total/10+1) == 0 || n == st.total-1 {
			return fmt.Sprintf("upload %d/%d chunks", n, st.total), nil
		}
		return "", nil
	}
	return finalizeFileUl()
}

func finalizeFileUl() (string, error) {
	fileUlMu.Lock()
	st := fileUlState
	fileUlState = nil
	fileUlMu.Unlock()
	if st == nil {
		return "", fmt.Errorf("no upload in progress")
	}
	info, err := os.Stat(st.part)
	if err != nil {
		return "", err
	}
	if info.Size() != st.size {
		_ = os.Remove(st.part)
		return "", fmt.Errorf("upload size mismatch (%d != %d)", info.Size(), st.size)
	}
	if st.sha != "" {
		f, err := os.Open(st.part)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		buf := make([]byte, 1024*1024)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		f.Close()
		if hex.EncodeToString(h.Sum(nil)) != st.sha {
			_ = os.Remove(st.part)
			return "", fmt.Errorf("upload hash mismatch, retry (nothing written)")
		}
	}
	if err := os.Rename(st.part, st.path); err != nil {
		return "", err
	}
	return fmt.Sprintf("upload complete: %s (%d bytes, sha ok)", st.path, st.size), nil
}
