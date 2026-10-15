package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// NMS singleton: exactly one monitor per box. Two live rows for one host
// meant double probing and double clone attempts with two ledger views —
// the agent's singleton covers only the "full" role, so --nms needs its
// own guard. Generation-safe: the pid file carries pid + process create
// time, so PID recycling can never impersonate a live holder.

// ClaimNMSPid takes the monitor role: true = we own it. The initial
// create is atomic (O_EXCL: exactly one starter in the same second wins),
// so the old check-then-write race that doubled the rows is structurally
// impossible. A live matching holder means yield; stale/garbled/dead/
// mismatched means clear-and-retry (loser of the retry respects the
// winner); unreadable either way means run (a missing guard beats no
// monitor).
func ClaimNMSPid() bool {
	ours, err := ownPidRecord()
	if err != nil {
		return true
	}
	if err := createNMSPidExcl(ours); err == nil {
		return true
	}
	if holder, ok := readNMSPid(); ok {
		if holder.pid == ours.pid && holder.createMs == ours.createMs {
			return true // ourselves (re-entrant call)
		}
		if nmsPidAlive(holder) {
			return false
		}
	}
	_ = os.Remove(NMSPidPath())
	if err := createNMSPidExcl(ours); err == nil {
		return true
	}
	if holder, ok := readNMSPid(); ok && nmsPidAlive(holder) {
		return holder.pid == ours.pid && holder.createMs == ours.createMs
	}
	return true
}

// createNMSPidExcl creates the pid file atomically (fails if present).
func createNMSPidExcl(r nmsPidRec) error {
	f, err := os.OpenFile(NMSPidPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, werr := fmt.Fprintf(f, "%d\n%d\n", r.pid, r.createMs); werr != nil {
		f.Close()
		_ = os.Remove(NMSPidPath())
		return werr
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(NMSPidPath())
		return cerr
	}
	return nil
}

// ReleaseNMSPid drops the role, but only if we still own it (never delete
// a successor's file out from under it).
func ReleaseNMSPid() {
	ours, err := ownPidRecord()
	if err != nil {
		return
	}
	if holder, ok := readNMSPid(); ok && holder.pid == ours.pid && holder.createMs == ours.createMs {
		_ = os.Remove(NMSPidPath())
	}
}

type nmsPidRec struct {
	pid      int
	createMs int64
}

func ownPidRecord() (nmsPidRec, error) {
	self := os.Getpid()
	p, err := process.NewProcess(int32(self))
	if err != nil {
		return nmsPidRec{}, err
	}
	ms, err := p.CreateTime()
	if err != nil || ms <= 0 {
		return nmsPidRec{}, fmt.Errorf("no create time")
	}
	return nmsPidRec{pid: self, createMs: ms}, nil
}

func readNMSPid() (nmsPidRec, bool) {
	b, err := os.ReadFile(NMSPidPath())
	if err != nil {
		return nmsPidRec{}, false
	}
	parts := strings.Fields(string(b))
	if len(parts) != 2 {
		return nmsPidRec{}, false
	}
	pid, err1 := strconv.Atoi(parts[0])
	ms, err2 := strconv.ParseInt(parts[1], 10, 64)
	if err1 != nil || err2 != nil || pid <= 0 || ms <= 0 {
		return nmsPidRec{}, false
	}
	return nmsPidRec{pid: pid, createMs: ms}, true
}

// nmsPidAlive reports whether the recorded holder is that same process
// (existence + create-time match defeats PID recycling).
func nmsPidAlive(holder nmsPidRec) bool {
	p, err := process.NewProcess(int32(holder.pid))
	if err != nil {
		return false
	}
	ms, err := p.CreateTime()
	if err != nil || ms <= 0 {
		return false
	}
	return ms == holder.createMs
}
