//go:build windows

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Explicit-desktop GUI spawn. Children inherit their window station from
// the parent — and an agent launched outside the interactive station
// (service token, odd task context) then spawns permanently invisible
// UI: dialogs run their full lifecycle and exit clean while their own
// spawner can never enumerate them. Pinning lpDesktop to winsta0\default
// fixes that class outright; when pinning is impossible (no access) it
// fails LOUDLY, and spawnGUI falls back to the plain hidden spawn so
// behavior never regresses vs today.
var interactiveDesktop, _ = windows.UTF16PtrFromString(`winsta0\default`)

// guiProc is the slice of exec.Cmd our GUI spawns need: pid for pid
// files/taskkill, Wait for reaping and exit codes.
type guiProc interface {
	Pid() int
	Wait() error
}

type execProc struct{ cmd *exec.Cmd }

func (p *execProc) Pid() int { return p.cmd.Process.Pid }
func (p *execProc) Wait() error {
	return p.cmd.Wait()
}

type sysProc struct {
	pid    int
	handle windows.Handle
	done   chan error
}

func (p *sysProc) Pid() int { return p.pid }
func (p *sysProc) Wait() error { return <-p.done }

// spawnGUI starts name+args with no console, pinned to the interactive
// desktop. out/err may be nil (discarded).
// Falls back to a plain hidden spawn when the explicit desktop is
// unavailable, so behavior never regresses vs today.
func spawnGUI(name string, args []string, out, stderr *os.File) (guiProc, error) {
	if gp, err := spawnOnDesktop(name, args, out, stderr); err == nil {
		return gp, nil
	}
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

func spawnOnDesktop(name string, args []string, out, stderr *os.File) (guiProc, error) {
	parts := append([]string{name}, args...)
	quoted := make([]string, 0, len(parts))
	for _, p := range parts {
		quoted = append(quoted, windows.EscapeArg(p))
	}
	cmdline, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return nil, err
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESHOWWINDOW | windows.STARTF_USESTDHANDLES
	si.ShowWindow = windows.SW_HIDE
	si.Desktop = interactiveDesktop
	inherit := false
	setStd := func(f *os.File, dst *windows.Handle) error {
		if f == nil {
			return nil
		}
		h := windows.Handle(f.Fd())
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return err
		}
		*dst = h
		inherit = true
		return nil
	}
	var nullH windows.Handle
	if out == nil && stderr == nil {
		nul, err := windows.CreateFile(windows.StringToUTF16Ptr(`NUL`), windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			return nil, err
		}
		defer windows.CloseHandle(nul)
		if err := windows.SetHandleInformation(nul, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return nil, err
		}
		nullH = nul
		si.StdOutput = nul
		si.StdErr = nul
		inherit = true
	} else {
		if err := setStd(out, &si.StdOutput); err != nil {
			return nil, err
		}
		if err := setStd(stderr, &si.StdErr); err != nil {
			return nil, err
		}
		if !inherit {
			return nil, fmt.Errorf("no inheritable std handles")
		}
	}
	_ = nullH
	var pi windows.ProcessInformation
	err = windows.CreateProcess(nil, cmdline, nil, nil, inherit, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi)
	if err != nil {
		return nil, err
	}
	windows.CloseHandle(pi.Thread)
	p := &sysProc{pid: int(pi.ProcessId), handle: pi.Process, done: make(chan error, 1)}
	go func() {
		_, _ = windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		var code uint32
		_ = windows.GetExitCodeProcess(pi.Process, &code)
		windows.CloseHandle(pi.Process)
		if code == 0 {
			p.done <- nil
		} else {
			p.done <- fmt.Errorf("exit status %d", code)
		}
	}()
	return p, nil
}
