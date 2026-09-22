//go:build !windows

package main

import (
	"os/exec"
)

// hideWatchCmd is a no-op off Windows.
func hideWatchCmd(c *exec.Cmd) {}
