// Package mobile is the gomobile bind surface for the all-in-one
// Android app: the full controller core in-process (same MQTT buses,
// same login gate, same console on localhost) behind strings-only
// functions. No structs cross the boundary (gobind restriction).
package mobile

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"rmm/internal/controller"
	"rmm/internal/version"
)

var (
	coreMu  sync.Mutex
	coreSrv *controller.Server
	coreLog = newRingLog(200)
)

// Start boots the controller core. dataDir is the app-private dir
// (secrets + screens live there). The shell pre-places agent_token.txt,
// server.crt and server.key from the bundled build-time identity, so
// empty args mean "already placed" — but presence is VERIFIED, never
// assumed. uiPassword has no fallback: the operator types it.
// Returns "" on success, "error: …" on failure (never Go errors — the
// boundary speaks strings).
func Start(dataDir, agentToken, uiPassword, serverCert, serverKey string) string {
	coreMu.Lock()
	defer coreMu.Unlock()
	if coreSrv != nil {
		return ""
	}
	if strings.TrimSpace(uiPassword) == "" {
		return "error: UI password required"
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "error: datadir: " + err.Error()
	}
	place := func(name, val string) error {
		p := filepath.Join(dataDir, name)
		if v := strings.TrimSpace(val); v != "" {
			return os.WriteFile(p, []byte(v+"\n"), 0600)
		}
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return fmt.Errorf("missing %s (pass it or pre-place it)", name)
		}
		return nil
	}
	for _, kv := range [][2]string{
		{"agent_token.txt", agentToken},
		{"ui_password.txt", uiPassword},
		{"server.crt", serverCert},
		{"server.key", serverKey},
	} {
		if err := place(kv[0], kv[1]); err != nil {
			return "error: " + err.Error()
		}
	}
	// Secrets resolve from CWD (agent_token.txt, ui_password.txt): run
	// the core rooted at the app dir.
	if err := os.Chdir(dataDir); err != nil {
		return "error: chdir: " + err.Error()
	}
	if err := os.MkdirAll("screens", 0700); err != nil {
		return "error: screens: " + err.Error()
	}
	log.SetOutput(coreLog)
	opts := controller.Options{
		Addr:           "127.0.0.1:4444",
		CertFile:       filepath.Join(dataDir, "server.crt"),
		KeyFile:        filepath.Join(dataDir, "server.key"),
		HTTPAddr:       "127.0.0.1:8080",
		House:          "Tablet",
		ScreensDir:     "screens",
		EnableTCPRelay: false,
	}
	srv, err := controller.StartBackground(opts)
	if err != nil {
		return "error: " + err.Error()
	}
	coreSrv = srv
	return ""
}

// Stop shuts the core down. Safe to call when already stopped.
func Stop() string {
	coreMu.Lock()
	defer coreMu.Unlock()
	if coreSrv == nil {
		return ""
	}
	coreSrv.Close()
	coreSrv = nil
	return ""
}

// Status reports core state as JSON: running, suite version, and the
// visible agents (hostname/user/version/id). Agents connect over the
// public MQTT buses — no inbound ports, no pairing.
func Status() string {
	coreMu.Lock()
	srv := coreSrv
	coreMu.Unlock()
	out := map[string]interface{}{
		"running": srv != nil,
		"version": version.Version,
		"agents":  []interface{}{},
	}
	if srv == nil {
		b, _ := json.Marshal(out)
		return string(b)
	}
	list := []interface{}{}
	for _, a := range srv.Agents() {
		list = append(list, map[string]interface{}{
			"hostname": strField(a, "hostname"),
			"user":     strField(a, "user"),
			"version":  strField(a, "version"),
			"id":       strField(a, "id"),
		})
	}
	out["agents"] = list
	b, _ := json.Marshal(out)
	return string(b)
}

// LogTail returns the last n core log lines (newest last).
func LogTail(n int) string {
	if n <= 0 {
		n = 50
	}
	if n > 500 {
		n = 500
	}
	return strings.Join(coreLog.tail(n), "\n")
}

func strField(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

// ringLog is a tiny threadsafe log sink (log.SetOutput target).
type ringLog struct {
	mu  sync.Mutex
	buf []string
	cap int
}

func newRingLog(cap int) *ringLog { return &ringLog{cap: cap} }

func (r *ringLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ln := range strings.Split(string(p), "\n") {
		if ln == "" {
			continue
		}
		r.buf = append(r.buf, ln)
		for len(r.buf) > r.cap {
			r.buf = r.buf[1:]
		}
	}
	return len(p), nil
}

func (r *ringLog) tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > len(r.buf) {
		n = len(r.buf)
	}
	out := make([]string, n)
	copy(out, r.buf[len(r.buf)-n:])
	return out
}
