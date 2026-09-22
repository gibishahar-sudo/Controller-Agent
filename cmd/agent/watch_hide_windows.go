//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// hideWatchCmd starts children with no visible window.
func hideWatchCmd(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
