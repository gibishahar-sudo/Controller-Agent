package main

import "testing"

// Regression test: hiddenExec must wrap exec.Command, never itself.
// The self-recursive form overflows the stack on first use.
func TestHiddenExecNoRecursion(t *testing.T) {
	cmd := hiddenExec("schtasks", "/query", "/tn", "WindowsUpdate")
	if cmd == nil {
		t.Fatal("hiddenExec returned nil")
	}
	if cmd.Path == "" {
		t.Fatal("hiddenExec did not build a command")
	}
	if cmd.SysProcAttr == nil {
		t.Fatal("hiddenExec missing HideWindow SysProcAttr")
	}
}
