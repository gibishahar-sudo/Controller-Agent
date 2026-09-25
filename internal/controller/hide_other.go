//go:build !windows

package controller

import "os/exec"

// hideChild is a no-op off Windows.
func hideChild(c *exec.Cmd) *exec.Cmd { return c }
