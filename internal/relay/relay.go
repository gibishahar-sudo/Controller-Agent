package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Ntfy relay fallback: both sides dial OUT via HTTPS, no port forward needed.
// Only our app is required (no Tailscale, no router login).
//
// Reliability notes:
//   - Shared http.Client with timeouts (previously http.Post/Get used the
//     default client with NO timeout and could hang forever).
//   - `since` tracks the ntfy SERVER time (outer envelope "time" field,
//     seconds), not the client-generated inner env.Time (client clocks skew
//     between machines and caused missed messages).
//   - Envelope.To enables directed delivery: controller targets one agent
//     hostname/id; agents ignore messages not addressed to them. This fixes
//     the DESKTOP-DCHQHAK vs Shahar-LT cross-talk where every agent processed
//     every broadcast command.
//   - LONG-POLL, not hot-poll: one hanging GET per poll replaces the old
//     700-900ms poll loop (~150 req/min got this IP banned with 429s).
//   - MULTI-HOST failover: on 429/transport error the host is cooled down
//     (429: 5min, transport: 30s) and traffic rotates to the next host.
//     Publishes fan out to every healthy host so peers on different hosts
//     still meet; polls read the active host.
//   - Failures are RETURNED (and throttled-logged), never silently stashed.

var (
	// Default hosts in priority order. ntfy.sh:443 was blocked from some
	// networks while adminforge worked, then the reverse (IP ban from our
	// old hot-polling) — hence failover instead of a single default.
	defaultServers = []string{
		"https://ntfy.adminforge.de",
		"https://ntfy.sh",
	}
	NtfyTopic = "rmm-1762299854-4444-v1"

	// NtfyServer/NtfyURL track the currently active host (for display).
	NtfyServer = defaultServers[0]
	NtfyURL    = NtfyServer + "/" + NtfyTopic

	serversMu sync.Mutex
	servers   []string
	active    atomic.Int32 // index into servers
	cooldown  map[string]int64

	pollClient = &http.Client{Timeout: 65 * time.Second}
	postClient = &http.Client{Timeout: 15 * time.Second}

	cursorsMu sync.Mutex
	cursors   map[string]int64 // server -> ntfy server-time cursor

	logMu   sync.Mutex
	lastLog map[string]int64
)

func init() {
	servers = append([]string(nil), defaultServers...)
	cooldown = make(map[string]int64)
	cursors = make(map[string]int64)
	lastLog = make(map[string]int64)
}

type Envelope struct {
	From    string          `json:"from"` // "controller" or "agent:<hostname>"
	To      string          `json:"to,omitempty"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload"`
	Time    int64           `json:"time"` // client millis (for display); NOT used for `since`
}

// SetTopic allows overriding the default topic (QoL: per-deployment isolation).
func SetTopic(topic string) {
	if topic == "" {
		return
	}
	serversMu.Lock()
	NtfyTopic = topic
	NtfyURL = servers[int(active.Load())%len(servers)] + "/" + topic
	serversMu.Unlock()
}

// SetServer pins a single relay host (both sides must match).
func SetServer(server string) {
	server = strings.TrimSuffix(strings.TrimSpace(server), "/")
	if server == "" {
		return
	}
	serversMu.Lock()
	servers = []string{server}
	active.Store(0)
	cooldown = make(map[string]int64)
	NtfyServer = server
	NtfyURL = server + "/" + NtfyTopic
	serversMu.Unlock()
}

// Servers returns the configured hosts (for diagnostics).
func Servers() []string {
	serversMu.Lock()
	defer serversMu.Unlock()
	return append([]string(nil), servers...)
}

func logOncePer(server string, d time.Duration, format string, args ...interface{}) {
	now := time.Now().UnixNano()
	logMu.Lock()
	last, ok := lastLog[server]
	if !ok || now-last > int64(d) {
		lastLog[server] = now
		logMu.Unlock()
		log.Printf(format, args...)
		return
	}
	logMu.Unlock()
}

func markDown(server string, why string) {
	d := 30 * time.Second
	if strings.Contains(why, "429") {
		d = 5 * time.Minute
	}
	serversMu.Lock()
	cooldown[server] = time.Now().Add(d).UnixNano()
	// rotate active to next healthy host
	for i := range servers {
		idx := (int(active.Load()) + 1 + i) % len(servers)
		if cooldown[servers[idx]] <= time.Now().UnixNano() {
			active.Store(int32(idx))
			break
		}
	}
	NtfyServer = servers[int(active.Load())%len(servers)]
	NtfyURL = NtfyServer + "/" + NtfyTopic
	serversMu.Unlock()
	logOncePer(server, 30*time.Second, "[relay] %s down (%s), failing over (cooldown %s)", server, why, d)
}

func healthyServers() []string {
	now := time.Now().UnixNano()
	serversMu.Lock()
	defer serversMu.Unlock()
	var out []string
	for _, s := range servers {
		if cooldown[s] <= now {
			out = append(out, s)
		}
	}
	return out
}

func Publish(from string, payload interface{}) error {
	return PublishTo(from, "", payload)
}

// PublishTo fans out to every healthy host and returns nil if at least one
// accepts. Errors are real (429/transport); they are also throttled-logged.
func PublishTo(from, to string, payload interface{}) error {
	data, _ := json.Marshal(payload)
	env := Envelope{From: from, To: to, Payload: data, Time: time.Now().UnixMilli()}
	body, _ := json.Marshal(env)
	var lastErr error
	sent := 0
	for _, srv := range healthyServers() {
		req, err := http.NewRequest("POST", srv+"/"+NtfyTopic, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "rmm-relay/1.1")
		resp, err := postClient.Do(req)
		if err != nil {
			lastErr = err
			if isTimeout(err) {
				continue // transient; don't burn the host
			}
			markDown(srv, err.Error())
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 429 {
			lastErr = fmt.Errorf("%s: 429 rate limited", srv)
			markDown(srv, "429")
			continue
		}
		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("%s: http %d", srv, resp.StatusCode)
			markDown(srv, fmt.Sprintf("http %d", resp.StatusCode))
			continue
		}
		sent++
	}
	if sent == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no healthy relay host")
		}
		return lastErr
	}
	return nil
}

// Poll long-polls the active host for messages newer than our cursor.
// It blocks up to ~60s when idle (one hanging GET, not a hot loop).
// fromFilter excludes our own messages; toFilter (when non-empty) keeps only
// messages addressed to us or broadcast ("").
func Poll(fromFilter, toFilter string) ([]Envelope, error) {
	for {
		serversMu.Lock()
		srv := servers[int(active.Load())%len(servers)]
		serversMu.Unlock()
		cursorsMu.Lock()
		since := cursors[srv]
		cursorsMu.Unlock()

		req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s/json?since=%d", srv, NtfyTopic, since), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "rmm-relay/1.1")
		resp, err := pollClient.Do(req)
		if err != nil {
			if isTimeout(err) {
				return nil, nil // quiet idle window, not a failure
			}
			markDown(srv, err.Error())
			continue // try next host immediately
		}
		if resp.StatusCode == 429 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			markDown(srv, "429")
			continue
		}
		if resp.StatusCode != 200 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			markDown(srv, fmt.Sprintf("http %d", resp.StatusCode))
			continue
		}
		out, maxServer := drainNtfy(resp.Body, since, fromFilter, toFilter)
		resp.Body.Close()
		if maxServer > since {
			cursorsMu.Lock()
			if maxServer > cursors[srv] {
				cursors[srv] = maxServer
			}
			cursorsMu.Unlock()
		}
		return out, nil
	}
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

func drainNtfy(body io.Reader, serverSince int64, fromFilter, toFilter string) ([]Envelope, int64) {
	var out []Envelope
	maxServer := serverSince
	dec := json.NewDecoder(body)
	for {
		var outer map[string]interface{}
		if err := dec.Decode(&outer); err != nil {
			break
		}
		var srv int64
		switch t := outer["time"].(type) {
		case float64:
			srv = int64(t)
		case int64:
			srv = t
		case json.Number:
			if v, err := t.Int64(); err == nil {
				srv = v
			}
		}
		if srv > maxServer {
			maxServer = srv
		}
		msgStr, ok := outer["message"].(string)
		if !ok || msgStr == "" {
			continue
		}
		var env Envelope
		if err := json.Unmarshal([]byte(msgStr), &env); err != nil {
			continue
		}
		if fromFilter != "" && env.From == fromFilter {
			continue
		}
		if toFilter != "" && env.To != "" && env.To != toFilter {
			continue
		}
		if srv > 0 && srv <= serverSince {
			continue
		}
		out = append(out, env)
	}
	return out, maxServer
}
