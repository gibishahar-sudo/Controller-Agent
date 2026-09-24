package main

import (
	"strings"

	"rmm/internal/commands"
)

// Shared self-delete order handling (OS-independent). The teardown itself
// lives in selfdelete_windows.go / selfdelete_other.go. Intercepted in
// agent main on every transport before commands.Execute ever sees it, so
// it works in every operation mode (like set-mode, never gated).

// isDeleteCmd reports whether cmdStr is a self-delete order.
func isDeleteCmd(cmdStr string) bool {
	name, _ := splitCmd(cmdStr)
	return strings.EqualFold(name, "self-delete")
}

// handleSelfDelete processes one self-delete order. Two phases: "arm"
// returns a single-use nonce; "self-delete <nonce>" verifies it and starts
// teardown. reply delivers the output message. Returns true when the
// order was a delete order (handled).
func handleSelfDelete(cmdStr string, reply func(result, errStr string)) bool {
	if !isDeleteCmd(cmdStr) {
		return false
	}
	if commands.DeleteToken() == "" {
		reply("self-delete unavailable (no delete token on this install)", "")
		return true
	}
	_, args := splitCmd(cmdStr)
	if strings.EqualFold(strings.TrimSpace(args), "arm") {
		nonce := commands.ArmDelete()
		reply("DELETE-NONCE:"+nonce+" (valid 5min — send self-delete <nonce> to confirm PERMANENT removal)", "")
		return true
	}
	if !commands.VerifyDeleteNonce(args) {
		reply("self-delete denied (bad/expired nonce — send self-delete arm first)", "")
		return true
	}
	reply("self-delete confirmed — removing all persistence and exiting", "")
	go runSelfDelete()
	return true
}
