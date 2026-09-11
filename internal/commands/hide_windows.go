//go:build windows

package commands

import (
	"os/exec"
	"syscall"
)

// hideWindow suppresses the console window for child processes.
// Without this, every agent command flashes a conhost window on the remote
// PC (powershell/cmd/netsh/xcopy all do it).
func hideWindow(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}
