package commands

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
	chunks  map[int][]byte
}

// StartAgentUpdate begins a self-update transfer.
func StartAgentUpdate(version string, size int64, sha string, total int) (string, error) {
	if total <= 0 || total > 100000 {
		return "", fmt.Errorf("bad update manifest (total=%d)", total)
	}
	if size <= 0 || size > 256<<20 {
		return "", fmt.Errorf("bad update manifest (size=%d)", size)
	}
	updateMu.Lock()
	defer updateMu.Unlock()
	updateState = &updateSession{
		version: version,
		size:    size,
		sha:     sha,
		total:   total,
		chunks:  make(map[int][]byte),
	}
	return fmt.Sprintf("update %s accepted (%d bytes in %d chunks)", version, size, total), nil
}

// WriteUpdateChunk stores one chunk; finalizes (verify + swap + restart)
// when the set completes. Progress is reported every 10%.
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
	if _, dup := st.chunks[seq]; !dup {
		st.chunks[seq] = raw
	}
	n := len(st.chunks)
	done := n == st.total
	updateMu.Unlock()
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
		return "", fmt.Errorf("swap failed (need admin?): %v", err)
	}
	if err := os.WriteFile(exe, assembled, 0755); err != nil {
		_ = os.Rename(prevExe, exe) // best-effort rollback
		return "", fmt.Errorf("write failed, rolled back: %v", err)
	}
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
	From string `json:"from"`
	To   string `json:"to"`
	At   string `json:"at"`
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

// LoadRollbackNotice reads + consumes rollback_notice.json next to the exe.
// Returns nil when no rollback happened. The caller attaches Bad/To to
// every hello so the controller alarms + holds back the bad version.
func LoadRollbackNotice() *RollbackNotice {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	p := filepath.Join(filepath.Dir(exe), "rollback_notice.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	_ = os.Remove(p) // consume: report once, on every hello of this run
	var n RollbackNotice
	if err := json.Unmarshal(raw, &n); err != nil || n.Bad == "" {
		return nil
	}
	log.Printf("[!] Rolled back: v%s crash-looped, restored v%s", n.Bad, n.To)
	return &n
}
