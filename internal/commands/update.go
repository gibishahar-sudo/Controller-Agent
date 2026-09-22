package commands

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
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
	bak := exe + ".bak"
	_ = os.Remove(bak)
	// Windows allows renaming a running exe; Unix replaces the inode.
	if err := os.Rename(exe, bak); err != nil {
		return "", fmt.Errorf("swap failed (need admin?): %v", err)
	}
	if err := os.WriteFile(exe, assembled, 0755); err != nil {
		_ = os.Rename(bak, exe) // best-effort rollback
		return "", fmt.Errorf("write failed, rolled back: %v", err)
	}
	// Restart into the new binary; the singleton + watchdog dedupe any
	// overlap with task-triggered starts. If the spawn itself fails, roll
	// back so the old binary keeps running instead of bricking the remote.
	cmd := hideWindow(exec.Command(exe, os.Args[1:]...))
	if err := cmd.Start(); err != nil {
		_ = os.Remove(exe)
		_ = os.Rename(bak, exe)
		return "", fmt.Errorf("restart failed, rolled back: %v", err)
	}
	go func() {
		// Grace for the "updated" output to flush, then hand over.
		time.Sleep(1500 * time.Millisecond)
		os.Exit(0)
	}()
	return fmt.Sprintf("updated to %s, restarting", st.version), nil
}
