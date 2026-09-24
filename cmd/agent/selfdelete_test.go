package main

import (
	"strings"
	"testing"
)

// NOTE: the confirm path (valid nonce -> runSelfDelete -> os.Exit) is
// deliberately never exercised here: it would terminate the test process.

// isDeleteCmd matches the order name case-insensitively, nothing else.
func TestIsDeleteCmd(t *testing.T) {
	for _, c := range []string{"self-delete", "SELF-DELETE arm", "Self-Delete abc123"} {
		if !isDeleteCmd(c) {
			t.Fatalf("%q not recognized", c)
		}
	}
	for _, c := range []string{"", "kill-agent", "self-deletex", "xself-delete", "version"} {
		if isDeleteCmd(c) {
			t.Fatalf("%q falsely recognized", c)
		}
	}
}

// Without a delete token on disk, every order is refused (no teardown).
func TestHandleSelfDeleteNoToken(t *testing.T) {
	// Test binary has no delete_token.txt beside it.
	var got string
	if !handleSelfDelete("self-delete arm", func(res, errStr string) { got = res }) {
		t.Fatal("arm order not handled")
	}
	if !strings.Contains(got, "unavailable") {
		t.Fatalf("expected unavailable, got %q", got)
	}
	got = ""
	if !handleSelfDelete("self-delete deadbeef", func(res, errStr string) { got = res }) {
		t.Fatal("confirm order not handled")
	}
	if !strings.Contains(got, "unavailable") {
		t.Fatalf("expected unavailable, got %q", got)
	}
}

// Non-delete orders pass through untouched.
func TestHandleSelfDeletePassthrough(t *testing.T) {
	called := false
	if handleSelfDelete("kill-agent", func(res, errStr string) { called = true }) {
		t.Fatal("kill-agent claimed by delete handler")
	}
	if called {
		t.Fatal("reply invoked for non-delete order")
	}
}
