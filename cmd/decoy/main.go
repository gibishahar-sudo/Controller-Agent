// Command decoy builds the honeypot agent.exe stub placed in the legacy
// install dir (C:\Program Files\RMM\Agent). It looks like the pre-rename
// agent binary to anyone working from old notes, but it is NOT agent code:
// on execution it stamps a tripwire file the watcher notices, then exits
// immediately (no network, no persistence, no controller contact). Deleting
// it trips the wire too (absence is checked).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	hideOwnConsole()
	exe, err := os.Executable()
	if err == nil {
		marker := filepath.Join(filepath.Dir(exe), "decoy_exec.txt")
		_ = os.WriteFile(marker, []byte(fmt.Sprintf("executed at %s\n", time.Now().UTC().Format(time.RFC3339))), 0644)
	}
	// Pass as the old binary for a blink, then vanish: no output, no hang.
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}
