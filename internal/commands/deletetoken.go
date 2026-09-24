package commands

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Self-delete authorization (v1.44). The delete token is written by the
// installer to delete_token.txt (0600) next to the exe and travels with
// backups like token.txt. kill-agent is quiet-only; permanent removal
// requires this token plus a single-use nonce (two-phase: arm -> confirm).

func deleteTokenPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "delete_token.txt")
	}
	return filepath.Join(os.TempDir(), "delete_token.txt")
}

// DeleteToken returns the stored self-delete token ("" when absent, in
// which case self-delete is unavailable).
func DeleteToken() string {
	b, err := os.ReadFile(deleteTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

var deleteNonceMu sync.Mutex
var deleteNonce string
var deleteNonceAt time.Time

const deleteNonceTTL = 5 * time.Minute

// ArmDelete issues a single-use confirmation nonce (valid 5 minutes).
// Any previous nonce is revoked.
func ArmDelete() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand failure is non-recoverable; zero nonce still single-use
	nonce := hex.EncodeToString(b[:])
	deleteNonceMu.Lock()
	deleteNonce, deleteNonceAt = nonce, time.Now()
	deleteNonceMu.Unlock()
	return nonce
}

// VerifyDeleteNonce checks a presented nonce in constant time. A nonce is
// single-use: success or mismatch both burn the outstanding one, so
// guessing is one-shot per arm.
func VerifyDeleteNonce(nonce string) bool {
	nonce = strings.TrimSpace(nonce)
	deleteNonceMu.Lock()
	defer deleteNonceMu.Unlock()
	ok := deleteNonce != "" &&
		time.Since(deleteNonceAt) < deleteNonceTTL &&
		len(nonce) == len(deleteNonce) &&
		subtle.ConstantTimeCompare([]byte(nonce), []byte(deleteNonce)) == 1
	deleteNonce = ""
	return ok
}
