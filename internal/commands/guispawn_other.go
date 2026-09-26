//go:build !windows

package commands

import (
	"os"
	"os/exec"
)

// Non-Windows: plain spawn (hideWindow is a no-op off Windows).
type guiProc interface {
	Pid() int
	Wait() error
}

type execProc struct{ cmd *exec.Cmd }

func (p *execProc) Pid() int { return p.cmd.Process.Pid }
func (p *execProc) Wait() error {
	return p.cmd.Wait()
}

func spawnGUI(name string, args []string, out, stderr *os.File) (guiProc, error) {
	cmd := hideWindow(exec.Command(name, args...))
	if out != nil {
		cmd.Stdout = out
	}
	if stderr != nil {
		cmd.Stderr = stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &execProc{cmd: cmd}, nil
}
