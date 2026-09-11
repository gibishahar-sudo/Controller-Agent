//go:build windows

package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// psRunner keeps ONE powershell.exe alive and feeds it scripts over stdin.
// Spawning powershell costs ~300-500ms per call (.NET JIT); reuse drops that
// to ~20-50ms. This is the single biggest latency win for command-heavy
// flows (audio meter at 2Hz, rapid terminal use).
//
// Protocol per call: write the script lines, then a sentinel line that prints
// a unique marker with the exit code. Read stdout until the marker.
// A mutex serializes calls (one runspace). On any failure the process is
// killed and the next call starts a fresh one; the failed call falls back to
// a one-shot spawn so it still completes.
type psRunner struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	sc     *bufio.Scanner
	seq    atomic.Uint64
	broken atomic.Bool
}

var sharedPS = &psRunner{}

func (r *psRunner) ensure() error {
	if r.cmd != nil && !r.broken.Load() {
		return nil
	}
	r.close()
	cmd := hideWindow(exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout // merge so error text is captured in order
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), maxOutputBytes+1024)
	r.cmd, r.stdin, r.sc = cmd, stdin, sc
	r.broken.Store(false)
	return nil
}

func (r *psRunner) close() {
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
		_ = r.cmd.Wait()
	}
	r.cmd, r.stdin, r.sc = nil, nil, nil
}

type psResult struct {
	out string
	err error
}

// run executes script in the shared shell with a timeout.
func (r *psRunner) run(script string, timeout time.Duration) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensure(); err != nil {
		return "", err
	}
	nonce := fmt.Sprintf("__RMM_END_%d__", r.seq.Add(1))
	// NOTE: scripts must not contain a bare `exit` (it would kill the shell);
	// none of ours do (shutdown uses shutdown.exe).
	wrapped := script + "\nWrite-Output \"" + nonce + ":$LASTEXITCODE\"\n"
	done := make(chan psResult, 1)
	go func(sc *bufio.Scanner, stdin io.WriteCloser) {
		if _, err := io.WriteString(stdin, wrapped); err != nil {
			done <- psResult{"", err}
			return
		}
		var b bytes.Buffer
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, nonce+":") {
				done <- psResult{b.String(), nil}
				return
			}
			b.WriteString(line)
			b.WriteByte('\n')
			if b.Len() > maxOutputBytes+1024 {
				// keep draining until the marker so the shell stays in sync
				for sc.Scan() {
					if strings.HasPrefix(sc.Text(), nonce+":") {
						break
					}
				}
				out := b.String()
				done <- psResult{out[:maxOutputBytes], nil}
				return
			}
		}
		done <- psResult{b.String(), fmt.Errorf("powershell shell closed")}
	}(r.sc, r.stdin)

	select {
	case res := <-done:
		if res.err != nil {
			r.broken.Store(true)
		}
		return res.out, res.err
	case <-time.After(timeout):
		r.broken.Store(true)
		go r.close() // async: mutex held; close() doesn't lock
		return "", fmt.Errorf("timed out after %s", timeout)
	}
}

// execPSPlatform runs a script in the persistent shell, falling back to a
// one-shot spawn if the shared shell is wedged.
func execPSPlatform(script string) (string, error) {
	return execPSShared(script, quickTimeout)
}

// execPSShared runs a script in the persistent shell, falling back to a
// one-shot spawn if the shared shell is wedged.
func execPSShared(script string, timeout time.Duration) (string, error) {
	out, err := sharedPS.run(script, timeout)
	if err == nil {
		return truncateStr(out), nil
	}
	// Fallback: one-shot (also covers non-Windows via runWithTimeout path —
	// this file is windows-only, but keep the shape symmetric).
	out2, err2 := runWithTimeout(timeout, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-command", script)
	if err2 != nil {
		return string(truncateOut(out2)), err2
	}
	return string(truncateOut(out2)), nil
}

func truncateStr(s string) string {
	if len(s) > maxOutputBytes {
		return s[:maxOutputBytes]
	}
	return strings.TrimRight(s, "\r\n")
}
