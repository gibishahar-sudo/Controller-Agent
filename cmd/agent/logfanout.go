package main

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// fanoutWriter writes every log line to every target, collecting errors
// instead of short-circuiting like io.MultiWriter (which stops at the
// first failing writer). One wedged file handle used to silently blind
// ALL standard logging for the process lifetime while the debug log kept
// growing — a day of hollow diagnostics. Failures are counted and
// reported on stderr, throttled to one warning per minute.
type fanoutWriter struct {
	ws       []io.Writer
	errCount atomic.Uint64
	lastWarn atomic.Int64
}

func (f *fanoutWriter) Write(p []byte) (int, error) {
	var firstErr error
	for _, w := range f.ws {
		if _, err := w.Write(p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		n := f.errCount.Add(1)
		now := time.Now().UnixNano()
		if last := f.lastWarn.Load(); now-last > int64(time.Minute) && f.lastWarn.CompareAndSwap(last, now) {
			fmt.Fprintf(os.Stderr, "[log] fanout target failed (%d total): %v\n", n, firstErr)
		}
		return 0, firstErr
	}
	return len(p), nil
}
