//go:build windows

package controller

import (
	"os/exec"
	"syscall"
)

// hideChild starts helpers with no visible window. The controller runs on
// the operator's own PC: audio playback, device queries and test tones
// spawn constantly, and every one of them would flash otherwise.
func hideChild(c *exec.Cmd) *exec.Cmd {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return c
}
