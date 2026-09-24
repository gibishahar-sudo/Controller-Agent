package commands

import (
	"strings"
	"testing"
	"time"
)

// Arm issues a 32-hex-char nonce.
func TestArmDeleteFormat(t *testing.T) {
	n := ArmDelete()
	if len(n) != 32 {
		t.Fatalf("nonce len = %d, want 32", len(n))
	}
	for _, c := range n {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("nonce %q not lowercase hex", n)
		}
	}
}

// Fresh nonce verifies exactly once (single-use).
func TestVerifyDeleteNonceSingleUse(t *testing.T) {
	n := ArmDelete()
	if !VerifyDeleteNonce(n) {
		t.Fatal("fresh nonce rejected")
	}
	if VerifyDeleteNonce(n) {
		t.Fatal("reused nonce accepted (must be single-use)")
	}
}

// Wrong nonce burns the outstanding one (one-shot per arm).
func TestVerifyDeleteNonceMismatchBurns(t *testing.T) {
	n := ArmDelete()
	bad := "0" + n[1:]
	if bad == n {
		bad = "1" + n[1:]
	}
	if VerifyDeleteNonce(bad) {
		t.Fatal("wrong nonce accepted")
	}
	if VerifyDeleteNonce(n) {
		t.Fatal("true nonce accepted after a mismatch (must be burned)")
	}
}

// Empty / garbage never verifies.
func TestVerifyDeleteNonceGarbage(t *testing.T) {
	ArmDelete()
	for _, g := range []string{"", "arm", "self-delete arm", strings.Repeat("x", 32), "short"} {
		if VerifyDeleteNonce(g) {
			t.Fatalf("garbage %q accepted", g)
		}
	}
}

// Expired nonce fails: backdate the issue time past the TTL.
func TestVerifyDeleteNonceExpiry(t *testing.T) {
	n := ArmDelete()
	deleteNonceMu.Lock()
	deleteNonceAt = time.Now().Add(-deleteNonceTTL - time.Minute)
	deleteNonceMu.Unlock()
	if VerifyDeleteNonce(n) {
		t.Fatal("expired nonce accepted")
	}
}

// Arming twice revokes the first nonce.
func TestArmDeleteRevokesPrevious(t *testing.T) {
	first := ArmDelete()
	ArmDelete()
	if VerifyDeleteNonce(first) {
		t.Fatal("revoked (first) nonce accepted after re-arm")
	}
}
