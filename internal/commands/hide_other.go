//go:build !windows

package commands

import "os/exec"

// hideWindow is a no-op off Windows.
func hideWindow(cmd *exec.Cmd) *exec.Cmd { return cmd }
