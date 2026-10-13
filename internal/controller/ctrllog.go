package controller

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// Controller file log (v1.49.12): the controller ran with stdout void
// (windowsgui) and zero disk logging, so every past controller death was
// uninvestigable — agents saw refusals, nobody knew why. Now startup,
// clean shutdown, and main-goroutine panics land in controller.log beside
// the exe (5MB startup rotation, one backup). Steady-state volume is
// small (connect/disconnect/alarms); per-frame noise never logs here.

const ctrlLogMaxBytes = 5 * 1024 * 1024

// ctrlExeDirOverride swaps the log dir root in tests.
var ctrlExeDirOverride = ""

// ctrlLogDir mirrors llmHome: beside the exe (installed) or CWD (dev).
func ctrlLogDir() string {
	if ctrlExeDirOverride != "" {
		return ctrlExeDirOverride
	}
	base := ""
	if exe, err := os.Executable(); err == nil {
		base = filepath.Dir(exe)
	}
	if base == "" {
		if cwd, err := os.Getwd(); err == nil {
			base = cwd
		} else {
			base = "."
		}
	}
	return base
}

// SetupControllerLog opens controller.log (rotating past 5MB) and points
// the standard logger at file+stderr. Returns a shutdown func that logs
// the reason and flushes (call via defer in main).
func SetupControllerLog(app, version, detail string) func(string) {
	path := filepath.Join(ctrlLogDir(), "controller.log")
	if st, err := os.Stat(path); err == nil && st.Size() > ctrlLogMaxBytes {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("[ctrllog] open %s: %v (logging to stderr only)", path, err)
	} else {
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}
	log.Printf("=== %s %s starting (%s) ===", app, version, detail)
	return func(reason string) {
		log.Printf("=== %s stopping: %s ===", app, reason)
		if f != nil {
			_ = f.Sync()
			_ = f.Close()
		}
	}
}

// LogCrash recovers a main-goroutine panic into the log (stack included)
// instead of dying into the void, then re-panics to preserve exit codes.
// Goroutine panics elsewhere still terminate the process — Go offers no
// global hook — but startup + main-loop deaths (the observed class) land.
func LogCrash(app string) {
	if r := recover(); r != nil {
		buf := make([]byte, 64*1024)
		n := runtime.Stack(buf, false)
		log.Printf("=== %s FATAL PANIC: %v ===\n%s", app, r, buf[:n])
		panic(r)
	}
}
