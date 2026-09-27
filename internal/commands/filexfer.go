package commands

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MakeThumb renders a small JPEG preview (max 800px side) for decodable
// images. Returns an error for non-images or absurd sizes so the caller
// falls back to the full file. Cheap: config-decode guards before pixels.
func MakeThumb(path string) ([]byte, error) {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	switch ext {
	case "png", "jpg", "jpeg", "gif":
	default:
		return nil, fmt.Errorf("no thumbnail for .%s", ext)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return nil, err
	}
	if int64(cfg.Width)*int64(cfg.Height) > 60000000 {
		return nil, fmt.Errorf("image too large for thumbnail")
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	src, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	scale := 800.0 / float64(w)
	if float64(h) > float64(w) {
		scale = 800.0 / float64(h)
	}
	if scale > 1 {
		scale = 1
	}
	dw, dh := int(float64(w)*scale), int(float64(h)*scale)
	if dw < 1 {
		dw = 1
	}
	if dh < 1 {
		dh = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	// Box-average downscale (dependency-free): each dst pixel averages
	// its source rect, so thumbnails stay smooth at any ratio.
	for y := 0; y < dh; y++ {
		y0 := (y * h) / dh
		y1 := ((y + 1) * h) / dh
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < dw; x++ {
			x0 := (x * w) / dw
			x1 := ((x + 1) * w) / dw
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, a uint64
			var n uint64
			for sy := y0; sy < y1 && sy < h; sy++ {
				for sx := x0; sx < x1 && sx < w; sx++ {
					cr, cg, cb, ca := src.At(b.Min.X+sx, b.Min.Y+sy).RGBA()
					r += uint64(cr >> 8)
					g += uint64(cg >> 8)
					bl += uint64(cb >> 8)
					a += uint64(ca >> 8)
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(r / n), uint8(g / n), uint8(bl / n), uint8(a / n)})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 70}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Chunked file transfer engine (both directions). Downloads stream straight
// off disk (no whole-file memory); uploads reassemble in a .part file and
// rename into place only after size+sha verify.

// MaxFileXfer caps single transfers at 1GB (reliability over speed:
// chunked, resumable, disk-backed both ends — RAM stays flat).
const MaxFileXfer = 1 << 30

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
	if !ModeCanFileDl(AgentMode()) {
		return nil, fmt.Errorf("%s", ModeDenied(AgentMode()))
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
	path      string
	size      int64
	sha       string
	total     int
	part      string
	have      map[int]bool
	started   time.Time
	lastChunk time.Time // sliding activity: slow-but-moving 1GB uploads survive
}

// maxUlIdle abandons uploads idle this long (source deleted mid-upload,
// UI closed, agent restarted). Sliding, not from-start: a moving transfer
// never trips it no matter how slow the link.
const maxUlIdle = 2 * time.Hour

// StartFileUl begins an upload: creates the .part file (parents included).
// Crash-proof: a sidecar manifest (part + ".json") records have-chunks;
// a re-begin with a matching manifest resumes the surviving .part
// instead of wiping an hour of received chunks.
func StartFileUl(path string, size int64, sha string, total int) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	if !ModeCanFileUl(AgentMode()) {
		return "", fmt.Errorf("%s", ModeDenied(AgentMode()))
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
	// Idempotent begin: if the final file already matches size+sha,
	// a re-begin after a completed-but-unacked transfer is a no-op
	// instead of a full re-upload.
	if st, err := os.Stat(path); err == nil && st.Size() == size && size > 0 {
		if sha == "" || fileSHA(path) == sha {
			return fmt.Sprintf("upload complete: %s (already present, %d bytes)", path, size), nil
		}
	}
	part := path + ".part"
	if have, ok := readUlSidecar(part, path, size, sha, total); ok {
		fileUlState = &fileUlSession{path: path, size: size, sha: sha, total: total, part: part, have: have, started: time.Now(), lastChunk: time.Now()}
		return fmt.Sprintf("upload %s accepted (%d bytes in %d chunks, resumed %d/%d)", filepath.Base(path), size, total, len(have), total), nil
	}
	_ = os.Remove(part)
	_ = os.Remove(part + ".json")
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", err
	}
	f.Close()
	fileUlState = &fileUlSession{path: path, size: size, sha: sha, total: total, part: part, have: map[int]bool{}, started: time.Now(), lastChunk: time.Now()}
	return fmt.Sprintf("upload %s accepted (%d bytes in %d chunks)", filepath.Base(path), size, total), nil
}

// ulSidecar is the crash-resume manifest beside the .part file.
type ulSidecar struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	SHA   string `json:"sha"`
	Total int    `json:"total"`
	Have  []int  `json:"have"`
}

// writeUlSidecar persists received-chunk progress (best effort: a lost
// sidecar only costs re-transfer, never correctness).
func writeUlSidecar(st *fileUlSession) {
	have := make([]int, 0, len(st.have))
	for s := range st.have {
		have = append(have, s)
	}
	sort.Ints(have)
	b, err := json.Marshal(ulSidecar{Path: st.path, Size: st.size, SHA: st.sha, Total: st.total, Have: have})
	if err != nil {
		return
	}
	_ = os.WriteFile(st.part+".json", b, 0600)
}

// fileSHA streams a file's SHA-256 hex (1MB buffer, flat RAM).
func fileSHA(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
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
	return hex.EncodeToString(h.Sum(nil))
}

// compressRanges renders a have-set as "0-7,15-18" (inverse of
// ParseRanges; mirrors the controller's haveRanges for the wire).
func compressRanges(have map[int]bool, total int) string {
	var parts []string
	start := -1
	for i := 0; i <= total; i++ {
		if i < total && have[i] {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-1 == start {
				parts = append(parts, strconv.Itoa(start))
			} else {
				parts = append(parts, strconv.Itoa(start)+"-"+strconv.Itoa(i-1))
			}
			start = -1
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// uploadStatus reports transfer state for the refill loop:
// "upload have <total> <ranges|none> <path>" (path last: it may contain
// spaces), or "upload unknown <path>". Reads the live session first,
// then the crash sidecar on disk (agent restarts don't lose the answer).
func uploadStatus(arg string) (string, error) {
	path := strings.TrimSpace(arg)
	if path == "" {
		return "", fmt.Errorf("usage: upload-status <path>")
	}
	if !ModeCanFileUl(AgentMode()) {
		return "", fmt.Errorf("%s", ModeDenied(AgentMode()))
	}
	fileUlMu.Lock()
	st := fileUlState
	if st != nil && st.path == path {
		total := st.total
		cp := make(map[int]bool, len(st.have))
		for k, v := range st.have {
			cp[k] = v
		}
		fileUlMu.Unlock()
		return fmt.Sprintf("upload have %d %s %s", total, compressRanges(cp, total), path), nil
	}
	fileUlMu.Unlock()
	part := path + ".part"
	b, err := os.ReadFile(part + ".json")
	if err != nil {
		return fmt.Sprintf("upload unknown %s", path), nil
	}
	var sc ulSidecar
	if err := json.Unmarshal(b, &sc); err != nil || sc.Path != path {
		return fmt.Sprintf("upload unknown %s", path), nil
	}
	if _, err := os.Stat(part); err != nil {
		return fmt.Sprintf("upload unknown %s", path), nil
	}
	have := map[int]bool{}
	for _, s := range sc.Have {
		if s >= 0 && s < sc.Total {
			have[s] = true
		}
	}
	return fmt.Sprintf("upload have %d %s %s", sc.Total, compressRanges(have, sc.Total), path), nil
}

// readUlSidecar validates a surviving .part against the manifest and
// returns its have-set. Anything mismatched (or unreadable) means fresh.
func readUlSidecar(part, path string, size int64, sha string, total int) (map[int]bool, bool) {
	b, err := os.ReadFile(part + ".json")
	if err != nil {
		return nil, false
	}
	var sc ulSidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, false
	}
	if sc.Path != path || sc.Size != size || sc.SHA != sha || sc.Total != total {
		return nil, false
	}
	if _, err := os.Stat(part); err != nil {
		return nil, false
	}
	have := map[int]bool{}
	for _, s := range sc.Have {
		if s >= 0 && s < total {
			have[s] = true
		}
	}
	if len(have) == 0 {
		return nil, false
	}
	return have, true
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
	if time.Since(st.lastChunk) > maxUlIdle {
		_ = os.Remove(st.part)
		_ = os.Remove(st.part + ".json")
		fileUlState = nil
		fileUlMu.Unlock()
		return "", fmt.Errorf("upload session idle over 2h — restart the upload")
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
	st.lastChunk = time.Now()
	writeUlSidecar(st)
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
		_ = os.Remove(st.part + ".json")
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
			_ = os.Remove(st.part + ".json")
			return "", fmt.Errorf("upload hash mismatch, retry (nothing written)")
		}
	}
	if err := os.Rename(st.part, st.path); err != nil {
		return "", err
	}
	_ = os.Remove(st.part + ".json")
	return fmt.Sprintf("upload complete: %s (%d bytes, sha ok)", st.path, st.size), nil
}
