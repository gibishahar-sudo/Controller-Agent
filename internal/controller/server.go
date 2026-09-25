// Package controller is the single shared implementation behind the three
// controller binaries (cmd/controller headless, cmd/controller-ui browser,
// cmd/controller-native WebView2). It previously existed as three drifted
// copies of an 800-line main.go (fixed via patch_native.py); unifying here
// means a fix lands everywhere at once.
//
// Reliability fixes vs the old copies:
//   - idCounter is atomic (was a plain int incremented from 6 accept loops).
//   - Real RTT latency via pingSent timestamps (was UnixMilli stored as "latency").
//   - Per-connection WS write mutex (gorilla Conn is not safe for concurrent
//     WriteMessage; handleAgent + relay loops + HTTP handlers wrote concurrently).
//   - Nil-conn guards everywhere (MQTT virtual agents have no net.Conn).
//   - lastSeen + sweeper marks stale relay agents after 90s.
//   - Directed To delivery fixes cross-talk (DESKTOP-DCHQHAK executed
//     commands meant for Shahar-LT).
//   - Screenshots rotate (last 100 files) and reject >15MB payloads.
//   - HTTP server has read/write/idle timeouts + graceful shutdown.
package controller

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"rmm/internal/mqttrelay"
	"rmm/internal/protocol"
	"rmm/internal/relay"
	"rmm/internal/version"
)

const (
	relayStaleAfter  = 90 * time.Second
	sweepInterval   = 15 * time.Second
	maxScreensKept  = 100
	maxScreenBytes  = 15 << 20 // 15 MB decoded cap
	maxScannerBytes = 20 << 20
)

// Options configures the controller.
type Options struct {
	Addr         string // primary TLS listen, e.g. ":4444"
	ExtraAddrs   []string
	CertFile     string
	KeyFile      string
	HTTPAddr     string // "" disables UI
	House        string // operator label for multi-house setups (e.g. Home)
	ScreensDir   string
	AutoOpen     bool
	NtfyTopic    string // REMOVED in v1.45 (kept so old callers still compile)
	NtfyServer   string // REMOVED in v1.45 (kept so old callers still compile)
	EnableNtfy   bool   // REMOVED in v1.45 (kept so old callers still compile)
	EnableTCPRelay bool
}

// AgentConn wraps one agent (TCP or MQTT-virtual).
type AgentConn struct {
	conn     net.Conn // nil for MQTT-virtual agents
	enc      *json.Encoder
	hostname string
	user     string
	id       string
	version  string // DesktopAgentVersion from TypeConnect/hello ("" = old agent, unknown)
	// Crash-rollback report from hello: the watchdog restored the previous
	// binary after RollbackBad crash-looped. While set, update-all holds
	// back re-pushing the bad version.
	rollbackBad string
	rollbackTo  string
	// untrusted marks agents that connected without a registration token
	// (accepted only while auth enforcement is off).
	untrusted bool
	// prot is the watcher's persistence-layer score ("5/6", "" = unknown).
	prot string
	// protDetail is a sticky tamper tripwire ("decoy ... deleted", ...).
	protDetail string
	// mode is the agent operation mode from hello ("normal" when empty).
	mode string
	mu   sync.Mutex

	lastSeenMu sync.Mutex
	lastSeen   time.Time
	pingSentMu sync.Mutex
	pingSent   time.Time
}

func (a *AgentConn) send(msg protocol.Message) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.enc == nil || a.conn == nil {
		return fmt.Errorf("relay agent: use relay publish")
	}
	return a.enc.Encode(msg)
}

func (a *AgentConn) touch() {
	a.lastSeenMu.Lock()
	a.lastSeen = time.Now()
	a.lastSeenMu.Unlock()
}

func (a *AgentConn) seen() time.Time {
	a.lastSeenMu.Lock()
	defer a.lastSeenMu.Unlock()
	return a.lastSeen
}

func (a *AgentConn) remote() string {
	if a.conn == nil {
		if strings.HasPrefix(a.id, "agent-mqtt-") {
			return "mqtt"
		}
		return "ntfy"
	}
	return a.conn.RemoteAddr().String()
}

// transport reports how this agent is reached (for logs/UI).
func (a *AgentConn) transport() string {
	if strings.HasPrefix(a.id, "agent-mqtt-") {
		return "mqtt"
	}
	if strings.HasPrefix(a.id, "agent-ntfy-") {
		return "ntfy"
	}
	return "direct"
}

// mqttHost returns the MQTT topic host for directed commands. This MUST be
// the plain hostname: agents subscribe to cmd/<hostname> (their instance id
// is only used for the controller-side agent id, never for topics).
// Publishing to the instance id was a v1.4.6 regression that silently
// dropped every command to relay agents (they showed "connected" via hello
// but never received anything).
func (a *AgentConn) mqttHost() string {
	if a.hostname != "" {
		return a.hostname
	}
	if strings.HasPrefix(a.id, "agent-mqtt-") {
		return strings.TrimPrefix(a.id, "agent-mqtt-")
	}
	return a.id
}

// Server is a running controller instance.
type Server struct {
	opts        Options
	listeners   []net.Listener
	primary     net.Listener
	httpSrv     *http.Server
	tlsCfg      *tls.Config
	idCounter   atomic.Int64
	closed      atomic.Bool
	closeCh     chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup
	screenshotN atomic.Int64
	lastScreenRotate atomic.Int64

	agents        map[string]*AgentConn
	agentsMu      sync.RWMutex
	currentAgent  *AgentConn
	peers         map[string]peerInfo // live peer controllers by ctrl id
	peersMu       sync.Mutex
	pending       map[string]*pendingCmd // relay commands awaiting output
	pendingMu     sync.Mutex
	desiredMode   map[string]string // agentID → mode we keep retrying until hello confirms
	desiredMu     sync.Mutex
	desiredUpd    map[string]string // hostname → agent version we keep pushing until hello confirms
	desiredUpdMu  sync.Mutex
	updInflight   map[string]time.Time // hostname → push start (blocks double-push)
	updInflightMu sync.Mutex
	updLastTry    map[string]time.Time // hostname → last push attempt (debounces hello-driven resume)
	updLastMu     sync.Mutex
	updStaged     map[string]time.Time // hostname → staged-for-elevated-apply report (pauses hello resume 15min)
	updStagedMu   sync.Mutex
	certDaysLeft  int
	house         string
	latency       map[string]int64
	latencyMu     sync.RWMutex
	wsClients     map[*wsClient]bool
	wsMu          sync.Mutex
	ulSem         chan struct{} // bounds concurrent file-ul-chunk publishes
	screenSave    chan screenJob // background disk archival for frames
	camFrags      map[string]*camFragAsm
	camFragMu     sync.Mutex
	screenshotDir string
	httpAddr      string

	mqttMu       sync.Mutex
	mqttBus      *mqttrelay.CtrlBus // primary listener/publisher
	mqttBus2     *mqttrelay.CtrlBus // secondary listener on a different broker (split-brain guard)
	mqttLastMsg  atomic.Int64       // unixnano of last inbound MQTT message (either bus)
	mqttLastMsg1 atomic.Int64       // primary bus traffic (per-bus blackhole watchdog)
	mqttLastMsg2 atomic.Int64       // secondary bus traffic

	// End-to-end payload encryption (relay transports): per-agent AES data
	// keys, wrapped once by the agent with this controller's RSA public
	// key. Keyed by agent hostname. Absent key = plaintext peer (old
	// agent), which stays accepted for backward compatibility.
	rsaPriv *rsa.PrivateKey
	e2eMu   sync.Mutex
	e2eKeys map[string][32]byte

	// Auto-update: when true, an outdated hello triggers a bundled-binary
	// push without clicking Update All. autoPushed remembers the version
	// already pushed per agent id so re-announces don't re-push.
	autoUpdate atomic.Bool
	autoMu     sync.Mutex
	autoPushed map[string]string

	// Compressed update payloads, keyed by agent version (12MB exe gzips
	// to ~4MB, so relay pushes take a third of the time).
	gzipCache map[string]*gzipBlob
	gzipMu    sync.Mutex
	// Resume reports from agents ("update resume have N/M ranges ..."),
	// keyed by agent id. Lets an interrupted push send only missing chunks.
	updateHave map[string]haveReport
	haveMu     sync.Mutex

	// Server-side download sessions ("save to a path on this PC"),
	// keyed by agent id + NUL + remote path.
	dlTo   map[string]*dlToSession
	dlToMu sync.Mutex

	// Agent registration token (Track B): agents presenting a wrong token
	// are rejected; empty-token agents are accepted as untrusted unless
	// enforcement is on.
	agentToken  string
	enforceAuth atomic.Bool
	authLogMu   sync.Mutex
	authLog     map[string]time.Time

	// Disk-persisted crash-rollback holdbacks by hostname (Track D).
	heldBack map[string]heldRollback
	holdMu   sync.Mutex

	// Fleet groups v1.41: id -> group tag, persisted to groups.json.
	groups   map[string]string
	groupsMu sync.Mutex

	// Macros/runbooks v1.41: name -> ordered commands, persisted.
	macros   map[string][]string
	macrosMu sync.Mutex

	// Scheduler v1.41: per-agent cron entries persisted to scheduler.json.
	jobs   []schedJob
	jobsMu sync.Mutex
}

type schedJob struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Cmd    string `json:"cmd"`
	When   string `json:"when"`   // RFC3339 one-shot or cron stub
	Repeat string `json:"repeat"` // "once" | "hourly" | "daily"
	Group  string `json:"group,omitempty"`
}

type gzipBlob struct {
	data []byte
	sha  string
}

type haveReport struct {
	have  map[int]bool
	total int
	at    time.Time
}

type wsClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (c *wsClient) writeJSON(v interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.conn.WriteJSON(v)
}

func (c *wsClient) writeMsg(msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, msg)
}

var wsUpgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// StartBackground starts listeners, HTTP UI and relay dial-out.
// It returns immediately; call s.Close() to stop.
func StartBackground(opts Options) (*Server, error) {
	if opts.NtfyServer != "" || opts.NtfyTopic != "" {
		log.Printf("[!] ntfy relay was removed in v1.45 — NtfyServer/NtfyTopic ignored")
	}
	s := &Server{
		opts:      opts,
		agents:    make(map[string]*AgentConn),
		latency:   make(map[string]int64),
		wsClients: make(map[*wsClient]bool),
		ulSem:     make(chan struct{}, 8),
		screenSave: make(chan screenJob, 64),
		closeCh:   make(chan struct{}),
		httpAddr:  opts.HTTPAddr,
		house:     opts.House,
	}
	certFile := resolveCert(opts.CertFile, "server.crt")
	keyFile := resolveCert(opts.KeyFile, "server.key")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		if exe, e2 := os.Executable(); e2 == nil {
			altCert := filepath.Join(filepath.Dir(exe), "server.crt")
			altKey := filepath.Join(filepath.Dir(exe), "server.key")
			if c2, e3 := tls.LoadX509KeyPair(altCert, altKey); e3 == nil {
				cert, certFile, keyFile = c2, altCert, altKey
				err = nil
			}
		}
		if err != nil {
			showError(fmt.Sprintf("Failed to load TLS certificate:\n%v\n\nTried:\n  %s\n  %s\n\nReinstall or place server.crt/server.key next to exe.", err, certFile, keyFile))
			return nil, fmt.Errorf("load cert: %w", err)
		}
	}
	s.tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.e2eKeys = make(map[string][32]byte)
	s.autoPushed = make(map[string]string)
	s.gzipCache = make(map[string]*gzipBlob)
	s.updateHave = make(map[string]haveReport)
	s.groups = make(map[string]string)
	s.macros = make(map[string][]string)
	s.authLog = make(map[string]time.Time)
	s.loadAgentToken()
	s.loadHeldRollbacks()
	s.loadDesiredMode()
	s.loadDesiredUpdates()
	s.loadInventory()
	s.loadGroups()
	s.loadMacros()
	s.loadJobs()
	go s.schedLoop()
	if priv, ok := cert.PrivateKey.(*rsa.PrivateKey); ok {
		s.rsaPriv = priv
	} else {
		log.Printf("[e2e] no RSA private key: inbound key exchanges will be refused, relay stays plaintext")
	}
	// Cert-expiry guard: an expired server cert silently kills every direct
	// agent connection, so warn loudly while there is still time to rotate.
	if len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			s.certDaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
			if s.certDaysLeft < 0 {
				log.Printf("[!] TLS certificate EXPIRED %d days ago — direct connections will fail; regenerate with gencerts", -s.certDaysLeft)
			} else if s.certDaysLeft < 30 {
				log.Printf("[!] TLS certificate expires in %d days — regenerate with gencerts soon", s.certDaysLeft)
			} else {
				log.Printf("[*] TLS certificate valid for %d more days", s.certDaysLeft)
			}
		}
	}

	addrs := []string{opts.Addr, ":443", ":22", ":53", ":80", ":4445"}
	addrs = append(addrs, opts.ExtraAddrs...)
	seen := map[string]bool{}
	for _, a := range addrs {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		l, e := tls.Listen("tcp", a, s.tlsCfg)
		if e != nil {
			if strings.Contains(e.Error(), "Only one usage") {
				fmt.Printf("[!] Port %s in use, skipping\n", a)
			} else {
				fmt.Printf("[!] Listen %s failed: %v\n", a, e)
			}
			continue
		}
		fmt.Printf("[*] Controller listening on %s (TLS)\n", a)
		s.listeners = append(s.listeners, l)
		if s.primary == nil {
			s.primary = l
		}
		s.wg.Add(1)
		go func(ln net.Listener) {
			defer s.wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-s.closeCh:
						return
					default:
					}
					if strings.Contains(err.Error(), "closed") {
						return
					}
					log.Printf("accept %s: %v", ln.Addr(), err)
					time.Sleep(time.Second)
					continue
				}
				id := fmt.Sprintf("agent-%d", s.idCounter.Add(1))
				log.Printf("[+] Raw connection from %s -> %s via %s", conn.RemoteAddr(), id, ln.Addr())
				go s.handleAgent(conn, id)
			}
		}(l)
	}
	if len(s.listeners) == 0 {
		fmt.Printf("[!] No TLS listeners (all in use) - continuing with MQTT relay only\n")
	} else {
		var names []string
		for _, l := range s.listeners {
			names = append(names, l.Addr().String())
		}
		fmt.Printf("[*] Listening on %d port(s): %v\n", len(s.listeners), names)
	}

	s.screenshotDir = resolveScreensDir(opts.ScreensDir)
	if opts.HTTPAddr != "" {
		s.startHTTP(opts.HTTPAddr, s.screenshotDir)
		if ui := s.HTTPAddr(); ui != "" {
			log.Printf("[http] serving this controller's UI at http://%s/", ui)
			if h, _, err := net.SplitHostPort(ui); err != nil || (h != "" && h != "127.0.0.1" && h != "::1" && h != "localhost") {
				log.Printf("[!] HTTP UI is bound to %s (NOT loopback) and has NO password — anyone who can reach it controls every agent. Use 127.0.0.1 unless you need LAN access.", ui)
			}
		}
		if opts.AutoOpen {
			go func() {
				time.Sleep(500 * time.Millisecond)
				if ui := s.HTTPAddr(); ui != "" {
					openBrowser("http://" + ui + "/")
				}
			}()
		}
	}
	if opts.EnableNtfy {
		log.Printf("[!] ntfy relay was removed in v1.45 — EnableNtfy ignored")
	}
	if opts.EnableTCPRelay {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.tcpRelayLoop()
		}()
	}
	// MQTT relay is always on: outbound-only, cheap keepalive, and it is
	// currently the only transport reachable from restricted networks.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.mqttLoop()
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sweepLoop()
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cmdRetryLoop()
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.screenSaveLoop()
	}()
	return s, nil
}

// pendingCmd tracks a relay command awaiting its output so a lost packet
// can be retried once instead of silently vanishing. Agent-side CmdID
// dedupe makes redelivery safe (already-executed commands are suppressed,
// never re-run).
type pendingCmd struct {
	msg      protocol.Message
	targetID string
	sentAt   int64 // unixnano
	retries  int
}

func (s *Server) trackCmd(msg protocol.Message, targetID string) {
	if msg.Type != protocol.TypeCommand || msg.CmdID == "" {
		return
	}
	now := time.Now().UnixNano()
	s.pendingMu.Lock()
	if s.pending == nil {
		s.pending = map[string]*pendingCmd{}
	}
	if old, ok := s.pending[msg.CmdID]; ok {
		// Re-send (retry/failover): fresh attempt clock, kept retry count
		// so retries stay bounded instead of resetting forever.
		old.msg = msg
		old.targetID = targetID
		old.sentAt = now
	} else {
		s.pending[msg.CmdID] = &pendingCmd{msg: msg, targetID: targetID, sentAt: now}
	}
	s.pendingMu.Unlock()
}

// ackCmd clears a pending command when any output carrying its CmdID lands.
func (s *Server) ackCmd(cmdID string) {
	if cmdID == "" {
		return
	}
	s.pendingMu.Lock()
	delete(s.pending, cmdID)
	s.pendingMu.Unlock()
}

// cmdRetryLoop resends relay commands that produced no output within 10s.
// Normal commands: one retry then forgotten after 2min (at-most-once exec,
// at-least-once delivery). Mode commands: retry forever every 10s with a
// fresh CmdID (idempotent, dedup-bypassed) until the hello confirms — so a
// ghost asleep 30s or a relay drop never loses the order, even across
// restarts (desiredMode file survives, noteHello also re-sends).
func (s *Server) cmdRetryLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
		}
		now := time.Now().UnixNano()
		s.pendingMu.Lock()
		for id, p := range s.pending {
			lc := strings.ToLower(strings.TrimSpace(p.msg.Cmd))
			isMode := lc == "set-mode" || strings.HasPrefix(lc, "set-mode ") || lc == "get-mode"
			age := now - p.sentAt
			if !isMode && age > 120e9 {
				delete(s.pending, id)
				continue
			}
			// Mode: retry every 10s forever (until hello clears desiredMode
			// and pending is acked). Normal: one retry only.
			if isMode {
				if age > 10e9 {
					p.retries++
					msg := p.msg
					newID := fmt.Sprintf("retry-%d-%s", time.Now().UnixNano(), id)
					msg.CmdID = newID
					delete(s.pending, id)
					s.pending[newID] = &pendingCmd{msg: msg, targetID: p.targetID, sentAt: now, retries: p.retries}
					s.pendingMu.Unlock()
					if ac := s.getAgentByID(p.targetID); ac != nil {
						log.Printf("[retry] %s (mode) no output in 10s, retrying as %s via %s (%d)", id, newID, ac.id, p.retries)
						_ = s.sendToAgent(ac, msg)
					}
					s.pendingMu.Lock()
				}
				continue
			}
			if age > 10e9 && p.retries < 1 {
				p.retries++
				s.pendingMu.Unlock()
				if ac := s.getAgentByID(p.targetID); ac != nil {
					log.Printf("[retry] %s no output in 10s, resending via %s", id, ac.id)
					_ = s.sendToAgent(ac, p.msg)
				} else {
					s.pendingMu.Lock()
					delete(s.pending, id)
					s.pendingMu.Unlock()
				}
				s.pendingMu.Lock()
			}
		}
		s.pendingMu.Unlock()
	}
}

// HTTPAddr returns the actual bound HTTP UI address (host:port), which may
// differ from Options.HTTPAddr when the configured port was taken and an
// ephemeral port was used instead. "" means the UI is disabled/failed.
// Written once by startHTTP before StartBackground returns.
func (s *Server) HTTPAddr() string {
	return s.httpAddr
}

// e2eSet stores an agent data key from a keyxchg message.
// Key is the agent instance ID (e.g., "agent-mqtt-hostname-pid") to
// prevent key flapping when multiple agents share a hostname.
func (s *Server) e2eSet(agentID string, key [32]byte) {
	if agentID == "" {
		return
	}
	s.e2eMu.Lock()
	s.e2eKeys[agentID] = key
	s.e2eMu.Unlock()
}

// e2eGet fetches an agent data key. Absent = plaintext peer (old agent).
func (s *Server) e2eGet(agentID string) ([32]byte, bool) {
	s.e2eMu.Lock()
	defer s.e2eMu.Unlock()
	k, ok := s.e2eKeys[agentID]
	return k, ok
}

// e2eHas reports whether relay traffic with agent is end-to-end encrypted.
func (s *Server) e2eHas(agentID string) bool {
	_, ok := s.e2eGet(agentID)
	return ok
}

// e2eKeyxchg unwraps an agent data key (RSA-OAEP with our private key).
// Never logs key material, only the fact. agentID is the full agent ID
// (e.g., "agent-mqtt-hostname-pid") to prevent key flapping across
// multiple agents on the same hostname.
func (s *Server) e2eKeyxchg(agentID, wrappedB64 string) {
	if s.rsaPriv == nil || agentID == "" || wrappedB64 == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		log.Printf("[e2e] %s: bad keyxchg encoding", agentID)
		return
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.rsaPriv, raw, nil)
	if err != nil {
		log.Printf("[e2e] %s: keyxchg unwrap failed", agentID)
		return
	}
	if len(secret) != 32 {
		log.Printf("[e2e] %s: bad keyxchg length", agentID)
		return
	}
	var k [32]byte
	copy(k[:], secret)
	s.e2eSet(agentID, k)
	log.Printf("[e2e] encrypted relay channel established with %s", agentID)
}

// e2eDecryptEnv opens an Enc envelope payload using the sender's key.
// Returns the plaintext payload, or ok=false to drop the message.
// agentID is the full agent ID for per-instance key lookup.
func (s *Server) e2eDecryptEnv(agentID string, env relay.Envelope) (json.RawMessage, bool) {
	if !env.Enc {
		return env.Payload, true
	}
	key, ok := s.e2eGet(agentID)
	if !ok {
		log.Printf("[e2e] %s: sealed message without key, dropped", agentID)
		return nil, false
	}
	plain, err := relay.OpenPayload(key, env.Payload)
	if err != nil {
		log.Printf("[e2e] %s: open failed, dropped", agentID)
		return nil, false
	}
	return json.RawMessage(plain), true
}

// e2eSealMsg seals an outbound protocol message for a keyed agent.
// Falls back to plaintext (old agents). agentID is the full agent ID.
func (s *Server) e2eSealMsg(agentID string, msg protocol.Message) (json.RawMessage, bool) {
	key, ok := s.e2eGet(agentID)
	if !ok {
		b, _ := json.Marshal(msg)
		return b, false
	}
	b, err := json.Marshal(msg)
	if err != nil {
		bb, _ := json.Marshal(msg)
		return bb, false
	}
	sealed, err := relay.SealPayload(key, b)
	if err != nil {
		bb, _ := json.Marshal(msg)
		return bb, false
	}
	return sealed, true
}

// bundledAgentBin locates the agent binary shipped next to the controller
// (post-rename name first, pre-rename fallback for mixed installs).
// Also checks the agent's own install dirs so a plain Controller-Setup
// without a bundled payload can still push updates.
func (s *Server) bundledAgentBin() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if st, err := os.Stat(filepath.Join(dir, "MicrosoftWindowsClient.exe")); err == nil && !st.IsDir() {
			return filepath.Join(dir, "MicrosoftWindowsClient.exe")
		}
		if st, err := os.Stat(filepath.Join(dir, "agent.exe")); err == nil && !st.IsDir() {
			return filepath.Join(dir, "agent.exe")
		}
	}
	if st, err := os.Stat("MicrosoftWindowsClient.exe"); err == nil && !st.IsDir() {
		return "MicrosoftWindowsClient.exe"
	}
	if st, err := os.Stat("agent.exe"); err == nil && !st.IsDir() {
		return "agent.exe"
	}
	// Fallback: agent's own install locations (so Controller-Setup doesn't
	// strictly need to bundle the agent binary).
	for _, p := range []string{
		`C:\ProgramData\Microsoft\Windows\Update\MicrosoftWindowsClient.exe`,
		filepath.Join(os.Getenv("ProgramData"), "Microsoft", "Windows", "Update", "MicrosoftWindowsClient.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "RMM", "Agent", "MicrosoftWindowsClient.exe"),
		`C:\Program Files\RMM\Agent\MicrosoftWindowsClient.exe`,
	} {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// fileChunkRaw sizes one file-transfer chunk per transport. MQTT is roomy
// (HiveMQ verified ≥100KB) but 128KB keeps loss blast radius small.
func fileChunkRaw(ac *AgentConn) int {
	switch ac.transport() {
	case "mqtt":
		return 128 * 1024
	default:
		return 512 * 1024
	}
}

// fileAgentFor picks the transport for bulk file transfer. MQTT is
// preferred over a possibly-flaky direct TCP link. Falls back to the
// selected agent. Chunk replies may arrive under the sibling's id — both
// UI and dlTo sessions match by hostname+path, so this is transparent.
func (s *Server) fileAgentFor(ac *AgentConn) *AgentConn {
	if ac == nil {
		return nil
	}
	if ac.transport() == "mqtt" {
		return ac
	}
	if sib := s.siblingRelay(ac); sib != nil && sib.transport() == "mqtt" {
		return sib
	}
	return ac
}

// fileRoute resolves an explicit UI override ("mqtt"/"direct"/"" auto).
func (s *Server) fileRoute(ac *AgentConn, via string) (*AgentConn, error) {
	if ac == nil {
		return nil, fmt.Errorf("no agent")
	}
	switch via {
	case "mqtt":
		if r := s.fileAgentFor(ac); r.transport() == "mqtt" {
			return r, nil
		}
		return nil, fmt.Errorf("no MQTT link for %s", ac.hostname)
	case "direct":
		if ac.conn != nil {
			return ac, nil
		}
		return nil, fmt.Errorf("no direct link for %s", ac.hostname)
	default:
		return s.fileAgentFor(ac), nil
	}
}

// dlToSession is a server-side download: agent chunks land straight in a
// controller-local .part file (for "save to a path on this PC"), renamed
// into place on completion. Keyed by agent id + remote path.
type dlToSession struct {
	mu        sync.Mutex
	localPath string
	part      string
	chunkRaw  int
	total     int
	size      int64
	sha       string
	have      map[int]bool
	started   time.Time
	lastChunk time.Time
}

func (s *Server) dlToKey(host, remote string) string { return host + "\x00" + remote }

// senderHostname resolves a chunk sender to its hostname (sibling
// transports share it, so dlTo sessions keyed by hostname survive routing).
func (s *Server) senderHostname(id string) string {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	if ac, ok := s.agents[id]; ok {
		return ac.hostname
	}
	return ""
}

// startDlTo begins a server-side save (replaces any prior one for the same
// file) and kicks the agent streaming.
func (s *Server) startDlTo(ac *AgentConn, remote, local string) {
	chunkRaw := fileChunkRaw(ac)
	_ = os.MkdirAll(filepath.Dir(local), 0755)
	s.dlToMu.Lock()
	if s.dlTo == nil {
		s.dlTo = map[string]*dlToSession{}
	}
	key := s.dlToKey(ac.hostname, remote)
	s.dlTo[key] = &dlToSession{
		localPath: local, part: local + ".part",
		chunkRaw: chunkRaw, have: map[int]bool{}, started: time.Now(),
		lastChunk: time.Now(),
	}
	s.dlToMu.Unlock()
	_ = os.Remove(local + ".part")
	_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeFileDlReq, FilePath: remote, FileFrom: 0, FileChunk: chunkRaw})
	go s.dlToGapLoop(key, remote)
}

// haveRanges compresses a have-set into "0-7,12-20" form.
func haveRanges(have map[int]bool, total int) string {
	var parts []string
	start := -1
	for i := 0; i <= total; i++ {
		if i < total && have[i] {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if i-1 == start {
				parts = append(parts, strconv.Itoa(start))
			} else {
				parts = append(parts, fmt.Sprintf("%d-%d", start, i-1))
			}
			start = -1
		}
	}
	return strings.Join(parts, ",")
}

// dlToGapLoop re-requests missing ranges for a server-side save while it
// is incomplete and idle: the browser path has gap recovery, dlTo had
// none (one QoS0 hole stalled it to the 30min fail). Exits when the
// session completes, fails, or is replaced.
func (s *Server) dlToGapLoop(key, remote string) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	reqs := 0
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
		}
		s.dlToMu.Lock()
		sess, ok := s.dlTo[key]
		s.dlToMu.Unlock()
		if !ok {
			return
		}
		sess.mu.Lock()
		total, haveN := sess.total, len(sess.have)
		idle := time.Since(sess.lastChunk)
		var missing []int
		if total > 0 && haveN < total && idle >= 5*time.Second && reqs < 8 {
			for i := 0; i < total; i++ {
				if !sess.have[i] {
					missing = append(missing, i)
				}
			}
		}
		sess.mu.Unlock()
		if len(missing) == 0 {
			continue
		}
		host := strings.SplitN(key, "\x00", 2)[0]
		ac := s.findAgentByHostname(host)
		if ac == nil {
			continue
		}
		rac, err := s.fileRoute(ac, "")
		if err != nil {
			continue
		}
		sess.mu.Lock()
		ranges := haveRanges(sess.have, total)
		chunkRaw := sess.chunkRaw
		sess.mu.Unlock()
		reqs++
		log.Printf("[dlto] gap: %d/%d chunks idle, re-requesting (try %d)", len(missing), total, reqs)
		_ = s.sendToAgent(rac, protocol.Message{Type: protocol.TypeFileDlReq, FilePath: remote, FileFrom: missing[0], FileChunk: chunkRaw, FileHave: ranges})
	}
}

// handleFileDlChunk fans one agent chunk out to the browser AND feeds any
// active server-side save session for the same file.
func (s *Server) handleFileDlChunk(id string, msg protocol.Message) {
	var sess *dlToSession
	if host := s.senderHostname(id); host != "" {
		s.dlToMu.Lock()
		sess = s.dlTo[s.dlToKey(host, msg.FilePath)]
		s.dlToMu.Unlock()
	}
	if sess != nil {
		s.feedDlTo(id, sess, msg)
	}
	s.broadcastWS(map[string]interface{}{"type": "file-chunk", "id": id, "path": msg.FilePath, "seq": msg.FileSeq, "total": msg.FileTotal, "size": msg.FileSize, "sha": msg.FileSHA, "data": msg.Data, "error": msg.Error})
}

func (s *Server) dlToFail(id string, sess *dlToSession, remote, why string) {
	if host := s.senderHostname(id); host != "" {
		s.dlToMu.Lock()
		delete(s.dlTo, s.dlToKey(host, remote))
		s.dlToMu.Unlock()
	}
	_ = os.Remove(sess.part)
	s.broadcastWS(map[string]interface{}{"type": "file-progress", "id": id, "path": remote, "local": sess.localPath, "status": "failed", "error": why})
}

func (s *Server) feedDlTo(id string, sess *dlToSession, msg protocol.Message) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if msg.Error != "" {
		s.dlToFail(id, sess, msg.FilePath, msg.Error)
		return
	}
	if time.Since(sess.started) > 30*time.Minute {
		s.dlToFail(id, sess, msg.FilePath, "save stalled over 30min — retry the download")
		return
	}
	if sess.total == 0 && msg.FileTotal > 0 {
		sess.total = msg.FileTotal
		sess.size = msg.FileSize
		sess.sha = msg.FileSHA
		if int64(sess.total)*int64(sess.chunkRaw) > 300<<20 {
			s.dlToFail(id, sess, msg.FilePath, "file too large")
			return
		}
	}
	raw, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		s.dlToFail(id, sess, msg.FilePath, "bad chunk encoding")
		return
	}
	f, err := os.OpenFile(sess.part, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		s.dlToFail(id, sess, msg.FilePath, err.Error())
		return
	}
	_, err = f.WriteAt(raw, int64(msg.FileSeq)*int64(sess.chunkRaw))
	f.Close()
	if err != nil {
		s.dlToFail(id, sess, msg.FilePath, err.Error())
		return
	}
	sess.have[msg.FileSeq] = true
	sess.lastChunk = time.Now()
	s.broadcastWS(map[string]interface{}{"type": "file-progress", "id": id, "path": msg.FilePath, "local": sess.localPath, "sent": len(sess.have), "total": sess.total, "status": "saving"})
	if sess.total > 0 && len(sess.have) >= sess.total {
		if st, err := os.Stat(sess.part); err != nil || st.Size() != sess.size {
			s.dlToFail(id, sess, msg.FilePath, "size mismatch")
			return
		}
		if sess.sha != "" {
			f, err := os.Open(sess.part)
			if err != nil {
				s.dlToFail(id, sess, msg.FilePath, err.Error())
				return
			}
			h := sha256.New()
			buf := make([]byte, 1024*1024)
			for {
				n, err := f.Read(buf)
				if n > 0 {
					h.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
			f.Close()
			if hex.EncodeToString(h.Sum(nil)) != sess.sha {
				s.dlToFail(id, sess, msg.FilePath, "hash mismatch")
				return
			}
		}
		_ = os.Remove(sess.localPath)
		if err := os.Rename(sess.part, sess.localPath); err != nil {
			s.dlToFail(id, sess, msg.FilePath, err.Error())
			return
		}
		if host := s.senderHostname(id); host != "" {
			s.dlToMu.Lock()
			delete(s.dlTo, s.dlToKey(host, msg.FilePath))
			s.dlToMu.Unlock()
		}
		log.Printf("[file] saved %s -> %s (%d bytes)", msg.FilePath, sess.localPath, sess.size)
		s.broadcastWS(map[string]interface{}{"type": "file-progress", "id": id, "path": msg.FilePath, "local": sess.localPath, "sent": sess.total, "total": sess.total, "size": sess.size, "status": "done"})
		s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": fmt.Sprintf("Saved %s -> %s (%d bytes, sha ok)", msg.FilePath, sess.localPath, sess.size), "success": true})
	}
}

type camFragAsm struct {
	total int
	parts map[int]string
	at    time.Time
}

// isCamFragLine reports a single-line CAMFRAG camera fragment.
func isCamFragLine(result string) bool {
	f := strings.Fields(strings.TrimSpace(result))
	return len(f) >= 4 && f[0] == "CAMFRAG"
}

// assembleCamFrag feeds one CAMFRAG <id> <seq>/<total> <b64> line,
// returning the reassembled data-URL when the set completes. Assemblies
// older than a minute restart (stale frag ids never poison new shots);
// totals over 16 are refused.
func (s *Server) assembleCamFrag(id, line string) (string, bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 4 || f[0] != "CAMFRAG" {
		return "", false
	}
	var seq, total int
	if _, err := fmt.Sscanf(f[2], "%d/%d", &seq, &total); err != nil || total <= 0 || total > 16 || seq < 0 || seq >= total {
		return "", false
	}
	key := id + "\x00" + f[1]
	s.camFragMu.Lock()
	defer s.camFragMu.Unlock()
	if s.camFrags == nil {
		s.camFrags = map[string]*camFragAsm{}
	}
	a, ok := s.camFrags[key]
	if !ok || a.total != total || time.Since(a.at) > time.Minute {
		a = &camFragAsm{total: total, parts: map[int]string{}}
		s.camFrags[key] = a
	}
	a.parts[seq] = f[3]
	a.at = time.Now()
	if len(a.parts) < total {
		return "", false
	}
	var sb strings.Builder
	for i := 0; i < total; i++ {
		p, ok := a.parts[i]
		if !ok {
			return "", false
		}
		sb.WriteString(p)
	}
	delete(s.camFrags, key)
	return sb.String(), true
}

// updateProg emits a live progress event for the UI progress readout.
func (s *Server) updateProg(ac *AgentConn, sent, total int, status string) {
	s.broadcastWS(map[string]interface{}{
		"type": "update-progress", "id": ac.id, "hostname": ac.hostname,
		"sent": sent, "total": total, "status": status,
	})
}

// sendWithRetry delivers one update envelope, retrying once after a short
// pause (relay buses drop the occasional chunk; a single retry saves the
// whole multi-minute push from failing on one lost packet).
func (s *Server) sendWithRetry(ac *AgentConn, msg protocol.Message, what string) error {
	if err := s.sendToAgent(ac, msg); err == nil {
		return nil
	} else {
		log.Printf("[update] %s %s failed, retrying once: %v", ac.id, what, err)
		time.Sleep(time.Second)
		if err2 := s.sendToAgent(ac, msg); err2 != nil {
			return fmt.Errorf("%s failed after retry: %w", what, err2)
		}
		return nil
	}
}

// gzipPayload compresses the agent binary once per (version, size, mtime)
// triple (cached). Size+mtime bust the cache when the file on disk is
// replaced under us — a version-only key would keep serving stale bytes.
func (s *Server) gzipPayload(ver string, data []byte, size int64, mtime int64) *gzipBlob {
	key := fmt.Sprintf("%s|%d|%d", ver, size, mtime)
	s.gzipMu.Lock()
	defer s.gzipMu.Unlock()
	if b, ok := s.gzipCache[key]; ok && len(b.data) > 0 {
		return b
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	b := &gzipBlob{data: buf.Bytes(), sha: hex.EncodeToString(sum[:])}
	s.gzipCache[key] = b
	log.Printf("[update] gzipped %d -> %d bytes (%.0f%%)", len(data), len(b.data), 100*float64(len(b.data))/float64(len(data)))
	return b
}

// bundledAgentMeta reads the installer's provenance markers beside bin:
// agent_version.txt (payload version) and agent.sha256 (payload hash).
// Empty strings when absent (pre-v1.44.1 installs).
func bundledAgentMeta(bin string) (ver, sha string) {
	dir := filepath.Dir(bin)
	if b, err := os.ReadFile(filepath.Join(dir, "agent_version.txt")); err == nil {
		ver = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "agent.sha256")); err == nil {
		sha = strings.TrimSpace(strings.Fields(string(b))[0])
	}
	return ver, sha
}

// parseHaveRanges parses "0-9,12,15-20" into a set (inverse of the agent's
// rangesOf; total bounds the result).
func parseHaveRanges(rs string, total int) map[int]bool {
	have := map[int]bool{}
	for _, p := range strings.Split(rs, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(p, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				continue
			}
			for i := a; i <= b && i < total; i++ {
				if i >= 0 {
					have[i] = true
				}
			}
		} else if n, err := strconv.Atoi(p); err == nil && n >= 0 && n < total {
			have[n] = true
		}
	}
	return have
}

// noteUpdateHave records an agent's resume report ("update resume have N/M
// ranges ...") and finalize notices ("updated to X, restarting") from any
// transport's output path.
func (s *Server) noteUpdateHave(id, result string) {
	// Structured ack first (v1.44.1+ agents emit RMM-UACK total=N have=R):
	// strict line parse, no prose matching. Legacy agents lack the marker
	// and fall through to the substring paths below.
	for _, ln := range strings.Split(result, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "RMM-UACK ") {
			continue
		}
		var total int
		var haveStr string
		for _, f := range strings.Fields(ln) {
			if v, ok := strings.CutPrefix(f, "total="); ok {
				total, _ = strconv.Atoi(v)
			} else if v, ok := strings.CutPrefix(f, "have="); ok {
				haveStr = v
			}
		}
		if total <= 0 || total > 100000 {
			continue
		}
		have := parseHaveRanges(haveStr, total)
		s.haveMu.Lock()
		s.updateHave[id] = haveReport{have: have, total: total, at: time.Now()}
		s.haveMu.Unlock()
		log.Printf("[update] %s ack: has %d/%d chunks", id, len(have), total)
		return
	}
	if strings.Contains(result, "staged") && strings.Contains(result, "elevated apply") {
		s.agentsMu.RLock()
		ac, ok := s.agents[id]
		s.agentsMu.RUnlock()
		hn := id
		if ok && ac.hostname != "" {
			hn = ac.hostname
		}
		log.Printf("[update] %s: staged for elevated apply (%s)", hn, strings.TrimSpace(result))
		s.updStagedMu.Lock()
		if s.updStaged == nil {
			s.updStaged = map[string]time.Time{}
		}
		s.updStaged[hn] = time.Now()
		s.updStagedMu.Unlock()
		if ok {
			s.updateProg(ac, 1, 1, "staged")
			s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": fmt.Sprintf("update to %s: staged, waiting for elevated apply (watcher/service swaps on next run, completes when v%s checks in)", hn, version.DesktopAgentVersion), "success": true})
		}
		return
	}
	if strings.Contains(result, "update ") && strings.Contains(result, " accepted (") {
		// Fresh begin-ack (empty cache): record it so awaitHave stops
		// waiting instead of timing out and firing a spurious second
		// begin mid-push (that rewrite races in-flight chunks and
		// halves throughput — the 6-push crawl in v1.43.4).
		total := 0
		if i := strings.Index(result, " in "); i >= 0 {
			rest := strings.TrimSpace(result[i+len(" in "):])
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				total, _ = strconv.Atoi(fields[0])
			}
		}
		if total > 0 {
			s.haveMu.Lock()
			s.updateHave[id] = haveReport{have: map[int]bool{}, total: total, at: time.Now()}
			s.haveMu.Unlock()
			log.Printf("[update] %s begin accepted (%d chunks, fresh)", id, total)
		}
		return
	}
	if strings.Contains(result, "updated to ") && strings.Contains(result, "restarting") {
		s.agentsMu.RLock()
		ac, ok := s.agents[id]
		s.agentsMu.RUnlock()
		hn := id
		if ok && ac.hostname != "" {
			hn = ac.hostname
		}
		log.Printf("[update] %s: agent verifying+restarting (%s)", hn, strings.TrimSpace(result))
		if ok {
			s.updateProg(ac, 1, 1, "restarting")
			s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": fmt.Sprintf("update to %s: verified, restarting… (completes when v%s checks in)", hn, version.DesktopAgentVersion), "success": true})
		}
		return
	}
	idx := strings.Index(result, "update resume have ")
	if idx < 0 {
		return
	}
	rest := result[idx+len("update resume have "):]
	fields := strings.Fields(rest)
	if len(fields) < 1 {
		return
	}
	frac := strings.Split(fields[0], "/")
	if len(frac) != 2 {
		return
	}
	total, err := strconv.Atoi(frac[1])
	if err != nil || total <= 0 {
		return
	}
	have := map[int]bool{}
	if i := strings.Index(rest, "ranges "); i >= 0 {
		have = parseHaveRanges(rest[i+len("ranges "):], total)
	}
	s.haveMu.Lock()
	s.updateHave[id] = haveReport{have: have, total: total, at: time.Now()}
	s.haveMu.Unlock()
	log.Printf("[update] %s resume: has %d/%d chunks", id, len(have), total)
}

// awaitHave waits for the agent's resume report after update_begin (the
// agent replies from its on-disk chunk cache). Returns the have-set, which
// is empty on timeout (fresh full push).
func (s *Server) awaitHave(id string, since time.Time, timeout time.Duration) map[int]bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.haveMu.Lock()
		rep, ok := s.updateHave[id]
		s.haveMu.Unlock()
		if ok && rep.at.After(since) {
			return rep.have
		}
		time.Sleep(250 * time.Millisecond)
	}
	return map[int]bool{}
}

// pushAgentUpdate streams the bundled agent binary to one agent in
// per-transport chunks. The payload is gzipped (~3x smaller), the agent
// verifies SHA256, stashes the running exe as prev, swaps, and restarts (a
// crash loop gets rolled back by the watchdog, which then notifies us via
// hello). An interrupted push resumes: the agent reports cached chunks and
// only missing ones are sent. Progress lands in the UI live via
// update-progress events. Returns true if all chunks were sent.

// loadAgentToken reads the shared agent registration secret (creating one
// on first run next to the controller exe, else CWD).
func (s *Server) loadAgentToken() {
	cands := []string{"agent_token.txt"}
	if exe, err := os.Executable(); err == nil {
		cands = append([]string{filepath.Join(filepath.Dir(exe), "agent_token.txt")}, cands...)
	}
	for _, p := range cands {
		if b, err := os.ReadFile(p); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				s.agentToken = t
				return
			}
		}
	}
	var b [24]byte
	_, _ = rand.Read(b[:])
	s.agentToken = hex.EncodeToString(b[:])
	save := cands[0]
	if err := os.WriteFile(save, []byte(s.agentToken+"\n"), 0600); err != nil {
		log.Printf("[auth] cannot persist agent token, using ephemeral")
	} else {
		log.Printf("[auth] generated new agent registration token (%s)", save)
	}
}

// checkAuth vets one hello: wrong token is always rejected; empty token is
// accepted as untrusted unless enforcement is on. Rejections are logged at
// most every 10 minutes per id so rogue re-announces can't spam the log.
func (s *Server) checkAuth(msg protocol.Message, id string) (allow, untrusted bool) {
	if msg.Auth != "" && msg.Auth != s.agentToken {
		s.authLogMu.Lock()
		last, seen := s.authLog[id]
		if !seen || time.Since(last) > 10*time.Minute {
			s.authLog[id] = time.Now()
			s.authLogMu.Unlock()
			log.Printf("[auth] rejected %s (id=%s): wrong registration token", msg.Hostname, id)
		} else {
			s.authLogMu.Unlock()
		}
		return false, false
	}
	if s.enforceAuth.Load() && msg.Auth == "" {
		s.authLogMu.Lock()
		last, seen := s.authLog[id]
		if !seen || time.Since(last) > 10*time.Minute {
			s.authLog[id] = time.Now()
			s.authLogMu.Unlock()
			log.Printf("[auth] rejected %s (id=%s): no token while enforcement is on", msg.Hostname, id)
		} else {
			s.authLogMu.Unlock()
		}
		return false, false
	}
	return true, msg.Auth == ""
}
func (s *Server) pushAgentUpdate(ac *AgentConn, bin string) bool {
	data, err := os.ReadFile(bin)
	if err != nil {
		log.Printf("[update] read %s: %v", bin, err)
		s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": "push-update failed: cannot read bundled agent binary", "success": false})
		s.updateProg(ac, 0, 0, "failed")
		return false
	}
	if ac.version != "" && ac.version == version.DesktopAgentVersion {
		log.Printf("[update] %s already up to date (%s), skipping", ac.id, ac.version)
		s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("skip %s: already %s", ac.hostname, ac.version), "success": true})
		s.clearDesiredUpdate(ac.hostname)
		return true
	}
	// Hold back a version the agent already crash-rolled-back: re-pushing
	// it would crash-loop the remote again.
	s.agentsMu.RLock()
	rb := s.heldBad(ac.hostname, ac.rollbackBad)
	s.agentsMu.RUnlock()
	if rb != "" && rb == version.DesktopAgentVersion {
		log.Printf("[update] %s held back: v%s crash-rolled-back on %s, not re-pushing", ac.id, rb, ac.hostname)
		s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("hold %s: v%s crashed there before (rolled back to %s) — fix the build first", ac.hostname, rb, ac.rollbackTo), "success": false})
		s.updateProg(ac, 0, 0, "heldback")
		s.clearDesiredUpdate(ac.hostname)
		return false
	}
	// Bundled-binary provenance: refuse to push a stale or corrupt bundle
	// instead of bricking the remote into a re-push loop (agent would stamp
	// the new version over old bytes and never converge). Checked BEFORE
	// the desired queue so a bad bundle never queues.
	if metaVer, metaSHA := bundledAgentMeta(bin); metaVer != "" && metaVer != version.DesktopAgentVersion {
		log.Printf("[update] stale bundle: agent_version.txt=%s vs controller %s — refusing push to %s", metaVer, version.DesktopAgentVersion, ac.hostname)
		s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("stale bundle: bundled agent v%s ≠ controller v%s — reinstall Controller-Setup, or click ⬇ Install for the GitHub EncodedCommand fallback", metaVer, version.DesktopAgentVersion), "success": false})
		s.updateProg(ac, 0, 0, "failed")
		return false
	} else if metaSHA != "" {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != metaSHA {
			log.Printf("[update] bundled binary hash drift for %s — refusing push", ac.hostname)
			s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": "bundled agent binary failed its hash check (corrupt copy) — reinstall Controller-Setup, or click ⬇ Install for the GitHub EncodedCommand fallback", "success": false})
			s.updateProg(ac, 0, 0, "failed")
			return false
		}
	}
	// Single-flight per hostname: double-clicks and auto+manual races used
	// to interleave two pushes and confuse progress. Second caller gets a
	// clear "already pushing" instead of a silent mess.
	s.updInflightMu.Lock()
	if s.updInflight == nil {
		s.updInflight = map[string]time.Time{}
	}
	if since, ok := s.updInflight[ac.hostname]; ok && time.Since(since) < 10*time.Minute {
		s.updInflightMu.Unlock()
		s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("already pushing %s (started %s ago) — wait for it to finish", ac.hostname, time.Since(since).Round(time.Second)), "success": false})
		return false
	}
	s.updInflight[ac.hostname] = time.Now()
	s.updInflightMu.Unlock()
	defer func() {
		s.updInflightMu.Lock()
		delete(s.updInflight, ac.hostname)
		s.updInflightMu.Unlock()
	}()
	s.updLastMu.Lock()
	if s.updLastTry == nil {
		s.updLastTry = map[string]time.Time{}
	}
	s.updLastTry[ac.hostname] = time.Now()
	s.updLastMu.Unlock()
	// Remember the target until a hello confirms it: ghost sleep, relay
	// drop, or controller restart no longer loses the order. Cleared on
	// hello with the new version, on skip, or on holdback.
	s.setDesiredUpdate(ac.hostname, version.DesktopAgentVersion)
	// Route bulk update via the best link (MQTT sibling when the selected
	// record is direct-flaky), exactly like file transfers. Have
	// tracking follows the routed record so resume reports land.
	rac := s.fileAgentFor(ac)
	if rac == nil {
		rac = ac
	}
	if rac.id != ac.id {
		log.Printf("[update] %s: routing via %s sibling (%s) instead of %s", ac.hostname, rac.transport(), rac.id, ac.transport())
	}
	var binSize, binMtime int64
	if st, err := os.Stat(bin); err == nil {
		binSize = st.Size()
		binMtime = st.ModTime().UnixNano()
	}
	payload := s.gzipPayload(version.DesktopAgentVersion, data, binSize, binMtime)
	chunkRaw := 512 * 1024
	pacing := time.Duration(0)
	haveTimeout := 4 * time.Second
	lanes := 1
	slowWarn := ""
	switch rac.transport() {
	case "mqtt":
		// 2 lanes: chunk reassembly is order-tolerant, but 4 lanes at
		// 15ms burst ~11MB/s at a shared public broker and QoS0 drops
		// most of it (v1.43.4 needed 6 manual pushes for 30 chunks).
		chunkRaw = 128 * 1024
		pacing = 40 * time.Millisecond
		haveTimeout = 10 * time.Second
		lanes = 2
	}
	// Ghost wakes 45s every ~75s: a 4s/10s have-timeout always misses when
	// the order lands during the 30s dark window. Wait past one full cycle.
	s.agentsMu.RLock()
	isGhost := rac.mode == "ghost" || ac.mode == "ghost"
	s.agentsMu.RUnlock()
	if isGhost && haveTimeout < 80*time.Second {
		haveTimeout = 80 * time.Second
		slowWarn += " (ghost: waiting through sleep cycle)"
	}
	total := (len(payload.data) + chunkRaw - 1) / chunkRaw
	log.Printf("[update] pushing agent binary (gzipped %d bytes, %d chunks) to %s via %s%s", len(payload.data), total, ac.hostname, rac.transport(), slowWarn)
	s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("pushing update v%s (gzipped %d bytes, %d chunks via %s)%s", version.DesktopAgentVersion, len(payload.data), total, rac.transport(), slowWarn), "success": true})
	s.updateProg(ac, 0, total, "pushing")
	begin := protocol.Message{Type: protocol.TypeUpdateBegin, UpdateVer: version.DesktopAgentVersion, UpdateSize: int64(len(payload.data)), UpdateSHA: payload.sha, UpdateTotal: total, UpdateGzip: true, UpdateChunk: chunkRaw}
	// Multi-round converge: QoS0 relays drop packets, so one pass rarely
	// lands everything (v1.43.4 needed 6 manual pushes for 30 chunks).
	// Each round re-begins (the agent replies have/resume from its on-disk
	// cache — identical manifests never wipe it), sends only what's still
	// missing, then re-checks. One click now converges on its own; the
	// desired queue still covers whatever is left on the next hello.
	const maxRounds = 8
	haveCount := 0
	for round := 1; round <= maxRounds; round++ {
		timeout := haveTimeout
		if round > 1 && timeout < 6*time.Second {
			// Fast transports re-check quickly; ghost (80s) keeps its
			// window or every later round times out and resends-all
			// forever.
			timeout = 6 * time.Second
		}
		beginAt := time.Now()
		if err := s.sendWithRetry(rac, begin, fmt.Sprintf("update begin (round %d)", round)); err != nil {
			log.Printf("[update] begin failed: %v", err)
			s.updateProg(ac, haveCount, total, "failed")
			s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("update to %s FAILED at begin (%v) — kept queued, resumes on next hello", ac.hostname, err), "success": false})
			return false
		}
		// Have reports may arrive under either transport id (sibling
		// routing), so check both the selected and routed records.
		have := s.awaitHave(rac.id, beginAt, timeout)
		if len(have) == 0 && rac.id != ac.id {
			if h2 := s.awaitHave(ac.id, beginAt, time.Second); len(h2) > 0 {
				have = h2
			}
		}
		haveCount = len(have)
		var missing []int
		for i := 0; i < total; i++ {
			if !have[i] {
				missing = append(missing, i)
			}
		}
		if len(missing) == 0 {
			log.Printf("[update] %s: agent holds all %d chunks after %d round(s), waiting for verify+restart", ac.hostname, total, round)
			s.updateProg(ac, total, total, "waiting")
			waitNote := "auto-completes on hello"
			if isGhost {
				waitNote = "auto-completes on hello (note: ghost resets to normal mode after update)"
			}
			s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("update to %s: all chunks held, waiting for verify+restart (%s)", ac.hostname, waitNote), "success": true})
			return true
		}
		if round > 1 || len(have) > 0 {
			log.Printf("[update] %s round %d: have %d/%d, sending %d", ac.hostname, round, len(have), total, len(missing))
			s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("update round %d: agent kept %d/%d chunks, sending %d", round, len(have), total, len(missing)), "success": true})
			s.updateProg(ac, len(have), total, "pushing")
		}
		// Lane send: chunks are independent (the agent reassembles by
		// seq), so parallel lanes trade one-RTT-per-chunk serial latency
		// for throughput. Serial transports keep lanes == 1.
		var sent atomic.Int64
		sent.Store(int64(len(have)))
		jobs := make(chan int, len(missing))
		for _, i := range missing {
			jobs <- i
		}
		close(jobs)
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		var failOnce sync.Once
		var failed error
		for l := 0; l < lanes; l++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}
					end := (i + 1) * chunkRaw
					if end > len(payload.data) {
						end = len(payload.data)
					}
					chunk := protocol.Message{
						Type:      protocol.TypeUpdateChunk,
						UpdateSeq: i,
						Data:      base64.StdEncoding.EncodeToString(payload.data[i*chunkRaw : end]),
					}
					if err := s.sendWithRetry(rac, chunk, fmt.Sprintf("chunk %d", i)); err != nil {
						log.Printf("[update] %v", err)
						failOnce.Do(func() { failed = err; cancel() })
						return
					}
					n := int(sent.Add(1))
					if n%5 == 0 || n == total || total <= 10 {
						log.Printf("[update] %s: %d/%d chunks", ac.hostname, n, total)
						s.updateProg(ac, n, total, "pushing")
					}
					if pacing > 0 {
						time.Sleep(pacing)
					}
				}
			}()
		}
		wg.Wait()
		cancel()
		if failed != nil {
			s.updateProg(ac, int(sent.Load()), total, "failed")
			s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("update to %s FAILED in round %d at chunk %d/%d — kept queued, resumes on next hello (agent kept its cache)", ac.hostname, round, int(sent.Load()), total), "success": false})
			return false
		}
		haveCount = int(sent.Load())
		time.Sleep(500 * time.Millisecond) // let late arrivals land before re-checking
	}
	log.Printf("[update] %s: %d rounds done, agent holds ~%d/%d — kept queued, resumes on next hello", ac.hostname, maxRounds, haveCount, total)
	s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("update to %s: sent %d/%d after %d rounds — kept queued, resumes automatically on next hello (no need to re-click)", ac.hostname, haveCount, total, maxRounds), "success": true})
	// Fallback hint: if push is stuck or the bundle is unusable, the
	// Install button hands out the GitHub EncodedCommand installer line.
	s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": "fallback: click ⬇ Install for the EncodedCommand install one-liner (Agent-Setup.exe from GitHub)", "success": true})
	// Desired queue stays until the hello confirms: even if verify fails or
	// the agent disconnects mid-restart, the next hello re-pushes/resumes.
	return true
}

// pushAgentUpdateAll streams the bundled binary to every outdated connected
// agent, sequentially with a small gap (so relay buses aren't flooded).
// Agents that crash-rolled-back this exact version are held back, never
// re-pushed. Returns pushed/skipped/offline/heldback counts.
func (s *Server) pushAgentUpdateAll(bin string) (pushed, skipped, offline, heldback int) {
	// Snapshot outdated, online agents (copy ids so we don't hold the lock
	// while doing slow chunked sends).
	s.agentsMu.RLock()
	var targets []string
	for id, a := range s.agents {
		online := true
		if strings.HasPrefix(id, "agent-ntfy-") || strings.HasPrefix(id, "agent-mqtt-") {
			online = time.Since(a.seen()) <= relayStaleAfter
		}
		if !online {
			offline++
			continue
		}
		if a.version != "" && a.version == version.DesktopAgentVersion {
			skipped++
			continue
		}
		if hb := s.heldBad(a.hostname, a.rollbackBad); hb != "" && hb == version.DesktopAgentVersion {
			heldback++
			continue
		}
		targets = append(targets, id)
	}
	s.agentsMu.RUnlock()
	if len(targets) == 0 {
		s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("update-all: nothing to push (%d up to date, %d offline, %d held back after rollback)", skipped, offline, heldback), "success": true})
		return 0, skipped, offline, heldback
	}
	s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("update-all: pushing %d agent(s) (%d up to date, %d offline, %d held back skipped)", len(targets), skipped, offline, heldback), "success": true})
	// Fleet fan-out: direct/MQTT pushes run up to 3 at a time (independent
	// agents, independent topics).
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for _, id := range targets {
		ac := s.getAgentByID(id)
		if ac == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t *AgentConn) {
			defer wg.Done()
			defer func() { <-sem }()
			s.pushAgentUpdate(t, bin)
		}(ac)
	}
	wg.Wait()
	return len(targets), skipped, offline, heldback
}

// noteHello records version + rollback report from any hello transport,
// fires the rollback alarm on first sight, and kicks auto-update when
// enabled. Safe to call redundantly on re-announces.
func (s *Server) noteHello(id, hostname, ver, bad, to, prot, tamp, mode string) {
	s.agentsMu.Lock()
	ac, ok := s.agents[id]
	if ok {
		if ver != "" {
			ac.version = ver
		}
		prevBad := ac.rollbackBad
		prevProt := ac.prot
		prevTamp := ac.protDetail
		prevMode := ac.mode
		ac.rollbackBad, ac.rollbackTo = bad, to
		if prot != "" {
			ac.prot = prot
		}
		if tamp != "" {
			ac.protDetail = tamp
		}
		if mode != "" {
			ac.mode = mode
		}
		s.agentsMu.Unlock()
		if mode != "" && prevMode != mode {
			log.Printf("[mode] %s %s → %s", hostname, prevMode, mode)
			s.desiredMu.Lock()
			if want, ok := s.desiredMode[id]; ok && want == mode {
				delete(s.desiredMode, id)
				s.saveDesiredModeLocked()
				log.Printf("[mode] %s reached desired %s ✓", hostname, want)
				// Clear any lingering mode pendings for this host — we already landed.
				s.pendingMu.Lock()
				for pid, p := range s.pending {
					if p.targetID == id && strings.Contains(strings.ToLower(p.msg.Cmd), "set-mode") {
						delete(s.pending, pid)
					}
				}
				s.pendingMu.Unlock()
			}
			s.desiredMu.Unlock()
		}
		// If hello shows we still haven't reached the desired mode, retry
		// immediately (ghost just woke — next window is 30s away, don't wait
		// for the 10s pending timer). Eventual delivery even if pending expired
		// or controller restarted (desired file survives).
		s.desiredMu.Lock()
		want, needRetry := s.desiredMode[id]
		s.desiredMu.Unlock()
		if needRetry && mode != "" && mode != want {
			if ac2 := s.getAgentByID(id); ac2 != nil {
				cid := fmt.Sprintf("desired-%d", time.Now().UnixNano())
				log.Printf("[mode] %s still %s want %s — re-sending set-mode", hostname, mode, want)
				_ = s.sendToAgent(ac2, protocol.Message{Type: protocol.TypeCommand, Cmd: "set-mode " + want, CmdID: cid})
				s.trackCmd(protocol.Message{Type: protocol.TypeCommand, Cmd: "set-mode " + want, CmdID: cid}, id)
			}
		}
		if bad != "" && prevBad != bad {
			s.handleRollback(id, hostname, bad, to)
		}
		if prot != "" && prevProt != "" && protScore(prot) < protScore(prevProt) {
			s.handleProtDrop(id, hostname, prevProt, prot)
		}
		if tamp != "" && tamp != prevTamp {
			s.handleProtDrop(id, hostname, "quiet", "TAMPER: "+tamp)
		}
	} else {
		s.agentsMu.Unlock()
	}
	// Desired-update queue: hello is the source of truth. New version →
	// clear + celebrate; still old → resume push (debounced, skipped while
	// a push is already in flight). Survives ghost sleep (30s dark),
	// relay drops, and controller restarts (desired_updates.json).
	if ver != "" && hostname != "" {
		if want, ok := s.wantUpdate(hostname); ok {
			if ver == want {
				s.clearDesiredUpdate(hostname)
				s.updStagedMu.Lock()
				delete(s.updStaged, hostname)
				s.updStagedMu.Unlock()
				log.Printf("[update] %s reached v%s ✓", hostname, ver)
				s.evictSupersededDuplicates(hostname, id, ver)
				s.broadcastWS(map[string]interface{}{"type": "update-progress", "id": id, "hostname": hostname, "sent": 1, "total": 1, "status": "done"})
				s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": fmt.Sprintf("update to %s DONE ✓ now v%s", hostname, ver), "success": true})
			} else if ver != version.DesktopAgentVersion {
				s.updInflightMu.Lock()
				_, inflight := s.updInflight[hostname]
				s.updInflightMu.Unlock()
				s.updLastMu.Lock()
				last := s.updLastTry[hostname]
				s.updLastMu.Unlock()
				s.updStagedMu.Lock()
				stagedAt := s.updStaged[hostname]
				s.updStagedMu.Unlock()
				// A staged box needs no pushes: the watcher swaps + the
				// supervisor restarts within ~a minute. Pause auto-resume
				// 15min so we don't re-push (and re-stage) in a loop.
				if !stagedAt.IsZero() && time.Since(stagedAt) < 15*time.Minute {
					log.Printf("[update] %s staged %s ago, holding resume", hostname, time.Since(stagedAt).Round(time.Second))
				} else if !inflight && time.Since(last) > 60*time.Second {
					if ac2 := s.getAgentByID(id); ac2 != nil {
						if bin := s.bundledAgentBin(); bin != "" {
							log.Printf("[update] %s still v%s want v%s — resuming push", hostname, ver, want)
							s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": fmt.Sprintf("update to %s: still v%s, resuming push to v%s…", hostname, ver, want), "success": true})
							go s.pushAgentUpdate(ac2, bin)
						}
					}
				}
			} else {
				// Hello already carries the current build but a stale queue
				// entry survived (e.g. version bump mid-queue): drop it.
				s.clearDesiredUpdate(hostname)
			}
		}
	}
	// Disk-persisted holdback (Track D): survives controller restarts.
	// A hello without a report clears the entry once the agent moved past
	// the bad version (fresh installs report the current version).
	if bad != "" {
		s.setHeldRollback(hostname, bad, to)
	} else if ver != "" {
		s.clearHeldRollback(hostname, ver)
	}
	if bad == "" {
		s.maybeAutoUpdate(id)
	}
}

// heldRollback is a crash-rollback record persisted to disk so a controller
// restart never forgets which versions are held back, keyed by hostname.
type heldRollback struct {
	Bad string `json:"bad"`
	To  string `json:"to"`
	At  string `json:"at"`
}

// rollbackHoldFile lives next to the controller exe (else CWD).
func rollbackHoldFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "rollback_held.json")
	}
	return "rollback_held.json"
}

// loadHeldRollbacks restores holdbacks saved by a previous controller run.
func (s *Server) loadHeldRollbacks() {
	s.holdMu.Lock()
	defer s.holdMu.Unlock()
	s.heldBack = map[string]heldRollback{}
	b, err := os.ReadFile(rollbackHoldFile())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.heldBack)
	if s.heldBack == nil {
		s.heldBack = map[string]heldRollback{}
	}
}

// saveHeldRollbacksLocked persists the holdback map (caller holds holdMu).
func (s *Server) saveHeldRollbacksLocked() {
	b, _ := json.MarshalIndent(s.heldBack, "", " ")
	_ = os.WriteFile(rollbackHoldFile(), b, 0600)
}

func desiredModeFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "desired_modes.json")
	}
	return "desired_modes.json"
}
func (s *Server) loadDesiredMode() {
	s.desiredMu.Lock()
	defer s.desiredMu.Unlock()
	s.desiredMode = map[string]string{}
	b, err := os.ReadFile(desiredModeFile())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.desiredMode)
	if s.desiredMode == nil {
		s.desiredMode = map[string]string{}
	}
}
func (s *Server) saveDesiredModeLocked() {
	b, _ := json.MarshalIndent(s.desiredMode, "", " ")
	_ = os.WriteFile(desiredModeFile(), b, 0600)
}
func (s *Server) setDesiredMode(agentID, want string) {
	s.desiredMu.Lock()
	defer s.desiredMu.Unlock()
	if s.desiredMode == nil {
		s.desiredMode = map[string]string{}
	}
	s.desiredMode[agentID] = strings.ToLower(strings.TrimSpace(want))
	s.saveDesiredModeLocked()
}
func (s *Server) clearDesiredMode(agentID string) {
	s.desiredMu.Lock()
	defer s.desiredMu.Unlock()
	if s.desiredMode == nil {
		return
	}
	delete(s.desiredMode, agentID)
	s.saveDesiredModeLocked()
}

// desiredUpdates persists hostname → target agent version until a hello
// confirms it. Survives controller restarts, ghost sleep, relay drops:
// an interrupted push resumes on the next hello instead of needing a
// manual re-click.
func desiredUpdatesFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "desired_updates.json")
	}
	return "desired_updates.json"
}
func (s *Server) loadDesiredUpdates() {
	s.desiredUpdMu.Lock()
	defer s.desiredUpdMu.Unlock()
	s.desiredUpd = map[string]string{}
	b, err := os.ReadFile(desiredUpdatesFile())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.desiredUpd)
	if s.desiredUpd == nil {
		s.desiredUpd = map[string]string{}
	}
}
func (s *Server) saveDesiredUpdatesLocked() {
	b, _ := json.MarshalIndent(s.desiredUpd, "", " ")
	_ = os.WriteFile(desiredUpdatesFile(), b, 0600)
}
func (s *Server) setDesiredUpdate(hostname, ver string) {
	if hostname == "" || ver == "" {
		return
	}
	s.desiredUpdMu.Lock()
	defer s.desiredUpdMu.Unlock()
	if s.desiredUpd == nil {
		s.desiredUpd = map[string]string{}
	}
	s.desiredUpd[hostname] = ver
	s.saveDesiredUpdatesLocked()
}
func (s *Server) clearDesiredUpdate(hostname string) {
	if hostname == "" {
		return
	}
	s.desiredUpdMu.Lock()
	defer s.desiredUpdMu.Unlock()
	if s.desiredUpd == nil {
		return
	}
	delete(s.desiredUpd, hostname)
	s.saveDesiredUpdatesLocked()
}
func (s *Server) wantUpdate(hostname string) (string, bool) {
	s.desiredUpdMu.Lock()
	defer s.desiredUpdMu.Unlock()
	v, ok := s.desiredUpd[hostname]
	return v, ok
}

// sweepDesiredUpdates drops desired-update entries for hostnames with no
// connected agent and no push attempt in 24h (renamed/retired boxes).
func (s *Server) sweepDesiredUpdates() {
	s.desiredUpdMu.Lock()
	if len(s.desiredUpd) == 0 {
		s.desiredUpdMu.Unlock()
		return
	}
	var orphans []string
	for host := range s.desiredUpd {
		s.updLastMu.Lock()
		last := s.updLastTry[host]
		s.updLastMu.Unlock()
		if !last.IsZero() && time.Since(last) < 24*time.Hour {
			continue
		}
		if s.findAgentByHostname(host) != nil {
			continue
		}
		orphans = append(orphans, host)
	}
	for _, host := range orphans {
		delete(s.desiredUpd, host)
	}
	if len(orphans) > 0 {
		s.saveDesiredUpdatesLocked()
		log.Printf("[update] swept %d orphaned desired-update entries", len(orphans))
	}
	s.desiredUpdMu.Unlock()
	// Resume-report hygiene: drop have-sets older than an hour (a delayed
	// duplicate must never satisfy a future push's awaitHave; staleness is
	// already time-gated, this bounds the map).
	s.haveMu.Lock()
	for id, rep := range s.updateHave {
		if time.Since(rep.at) > time.Hour {
			delete(s.updateHave, id)
		}
	}
	s.haveMu.Unlock()
}

func (s *Server) setHeldRollback(hostname, bad, to string) {
	if hostname == "" || bad == "" {
		return
	}
	s.holdMu.Lock()
	defer s.holdMu.Unlock()
	if cur, ok := s.heldBack[hostname]; ok && cur.Bad == bad {
		return
	}
	s.heldBack[hostname] = heldRollback{Bad: bad, To: to, At: time.Now().UTC().Format(time.RFC3339)}
	s.saveHeldRollbacksLocked()
}

func (s *Server) clearHeldRollback(hostname, ver string) {
	if hostname == "" {
		return
	}
	s.holdMu.Lock()
	defer s.holdMu.Unlock()
	if cur, ok := s.heldBack[hostname]; ok && ver != cur.Bad {
		delete(s.heldBack, hostname)
		s.saveHeldRollbacksLocked()
	}
}

// heldBad returns the bad version held back for an agent: live hello report
// first, disk-persisted record second.
func (s *Server) heldBad(hostname, memBad string) string {
	if memBad != "" {
		return memBad
	}
	s.holdMu.Lock()
	defer s.holdMu.Unlock()
	if cur, ok := s.heldBack[hostname]; ok {
		return cur.Bad
	}
	return ""
}

// protScore parses a "5/6" layer score into its intact count (-1 unknown).
func protScore(p string) int {
	var a, b int
	if _, err := fmt.Sscanf(p, "%d/%d", &a, &b); err != nil {
		return -1
	}
	return a
}

// handleProtDrop alarms when an agent's persistence layers drop (someone is
// peeling tasks/keys/WMI): early warning before a total kill.
func (s *Server) handleProtDrop(id, hostname, prev, cur string) {
	log.Printf("[protect] DEGRADED: %s (%s) persistence %s -> %s — tampering likely, check the box", hostname, id, prev, cur)
	fmt.Printf("\n[PROTECT] %s (%s): layers %s -> %s — tampering likely\n> ", hostname, id, prev, cur)
	s.broadcastWS(map[string]interface{}{
		"type": "protection", "id": id, "hostname": hostname, "prev": prev, "cur": cur,
	})
	s.broadcastAgents()
}

// handleRollback alarms loudly (log + UI event + refreshed list) when an
// agent reports the watchdog restored its previous binary after a crash
// loop. The bad version stays held back from future pushes automatically.
func (s *Server) handleRollback(id, hostname, bad, to string) {
	log.Printf("[update] ROLLBACK ALARM: %s (%s) crashed on v%s — watchdog restored v%s. Holding back v%s.", hostname, id, bad, to, bad)
	fmt.Printf("\n[ROLLBACK] %s (%s): v%s crashed, restored v%s — v%s held back\n> ", hostname, id, bad, to, bad)
	s.broadcastWS(map[string]interface{}{
		"type": "rollback", "id": id, "hostname": hostname, "bad": bad, "to": to,
	})
	s.broadcastAgents()
}

// maybeAutoUpdate pushes the bundled binary to one outdated agent when the
// auto-update switch is on. Fires at most once per (agent, version): while
// the push is in flight the agent still reports the old version, so without
// the guard every re-announce would start another push.
func (s *Server) maybeAutoUpdate(id string) {
	if !s.autoUpdate.Load() {
		return
	}
	ac := s.getAgentByID(id)
	if ac == nil {
		return
	}
	s.agentsMu.RLock()
	ver, rb := ac.version, ac.rollbackBad
	s.agentsMu.RUnlock()
	if ver == version.DesktopAgentVersion {
		s.autoMu.Lock()
		delete(s.autoPushed, id)
		s.autoMu.Unlock()
		return
	}
	if ver == "" || (rb != "" && rb == version.DesktopAgentVersion) {
		return // unknown version, or held back after rollback
	}
	s.autoMu.Lock()
	if s.autoPushed[id] == version.DesktopAgentVersion {
		s.autoMu.Unlock()
		return
	}
	s.autoPushed[id] = version.DesktopAgentVersion
	s.autoMu.Unlock()
	bin := s.bundledAgentBin()
	if bin == "" {
		log.Printf("[update] auto-update: no bundled agent binary, skipping %s", id)
		return
	}
	log.Printf("[update] auto-update: pushing %s to %s (%s)", version.DesktopAgentVersion, ac.hostname, id)
	go s.pushAgentUpdate(ac, bin)
}

// resetMQTTBus drops both relay buses so mqttLoop re-dials (and
// re-measures brokers). Manual unstick lever behind /api/reconnect-relays.
func (s *Server) resetMQTTBus() {
	s.mqttMu.Lock()
	b, b2 := s.mqttBus, s.mqttBus2
	s.mqttBus, s.mqttBus2 = nil, nil
	s.mqttMu.Unlock()
	if b != nil {
		b.Close()
	}
	if b2 != nil {
		b2.Close()
	}
}

// Close stops listeners, HTTP server and background loops.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		for _, l := range s.listeners {
			_ = l.Close()
		}
		if s.httpSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.httpSrv.Shutdown(ctx)
		}
	})
}

// Wait blocks until Close is called.
func (s *Server) Wait() {
	<-s.closeCh
	s.wg.Wait()
}

// inventoryEntry is one persisted fleet record (see saveInventory).
type inventoryEntry struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	User     string `json:"user"`
	Version  string `json:"version"`
	Seen     int64  `json:"seen"`
}

// inventoryFile lives next to the controller exe (else CWD).
func inventoryFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "agents.json")
	}
	return "agents.json"
}

// loadInventory restores known agents from the previous run as offline
// entries (conn == nil) so the list survives controller restarts. Live
// hellos overwrite them in place.
func (s *Server) loadInventory() {
	b, err := os.ReadFile(inventoryFile())
	if err != nil {
		return
	}
	var entries []inventoryEntry
	if json.Unmarshal(b, &entries) != nil {
		return
	}
	s.agentsMu.Lock()
	defer s.agentsMu.Unlock()
	for _, e := range entries {
		if e.ID == "" || e.Hostname == "" {
			continue
		}
		if _, ok := s.agents[e.ID]; ok {
			continue
		}
		ac := &AgentConn{id: e.ID, hostname: e.Hostname, user: e.User, version: e.Version}
		ac.lastSeen = time.Unix(e.Seen, 0)
		s.agents[e.ID] = ac
	}
	log.Printf("[*] Loaded %d agent(s) from inventory", len(entries))
}

// saveInventory snapshots the fleet (including offline tombstones) to disk.
func (s *Server) saveInventory() {
	s.agentsMu.RLock()
	entries := make([]inventoryEntry, 0, len(s.agents))
	for _, a := range s.agents {
		if strings.HasPrefix(a.id, "manual-") || strings.HasPrefix(a.id, "conn-") {
			continue // UI-local placeholders, not real agents
		}
		entries = append(entries, inventoryEntry{
			ID: a.id, Hostname: a.hostname, User: a.user,
			Version: a.version, Seen: a.seen().Unix(),
		})
	}
	s.agentsMu.RUnlock()
	b, _ := json.MarshalIndent(entries, "", " ")
	_ = os.WriteFile(inventoryFile(), b, 0600)
}

func groupsFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "groups.json")
	}
	return "groups.json"
}
func macrosFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "macros.json")
	}
	return "macros.json"
}
func jobsFile() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "scheduler.json")
	}
	return "scheduler.json"
}
func (s *Server) loadGroups() {
	b, err := os.ReadFile(groupsFile())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.groups)
	if s.groups == nil {
		s.groups = make(map[string]string)
	}
}
func (s *Server) saveGroups() {
	s.groupsMu.Lock()
	defer s.groupsMu.Unlock()
	b, _ := json.MarshalIndent(s.groups, "", " ")
	_ = os.WriteFile(groupsFile(), b, 0600)
}
func (s *Server) loadMacros() {
	b, err := os.ReadFile(macrosFile())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.macros)
	if s.macros == nil {
		s.macros = make(map[string][]string)
	}
}
func (s *Server) saveMacros() {
	s.macrosMu.Lock()
	defer s.macrosMu.Unlock()
	b, _ := json.MarshalIndent(s.macros, "", " ")
	_ = os.WriteFile(macrosFile(), b, 0600)
}
func (s *Server) loadJobs() {
	b, err := os.ReadFile(jobsFile())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.jobs)
}
func (s *Server) saveJobs() {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	b, _ := json.MarshalIndent(s.jobs, "", " ")
	_ = os.WriteFile(jobsFile(), b, 0600)
}
func (s *Server) schedLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
		}
		now := time.Now()
		s.jobsMu.Lock()
		jobs := append([]schedJob(nil), s.jobs...)
		s.jobsMu.Unlock()
		for _, j := range jobs {
			when, err := time.Parse(time.RFC3339, j.When)
			if err != nil || now.Before(when) {
				continue
			}
			if j.Group != "" {
				s.agentsMu.RLock()
				for _, a := range s.agents {
					s.groupsMu.Lock()
					g := s.groups[a.id]
					s.groupsMu.Unlock()
					if g == j.Group {
						ac := a
						_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeCommand, Cmd: j.Cmd})
					}
				}
				s.agentsMu.RUnlock()
			} else {
				ac := s.getAgentByID(j.Target)
				if ac != nil {
					_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeCommand, Cmd: j.Cmd})
				}
			}
			if j.Repeat == "once" {
				s.jobsMu.Lock()
				nj := s.jobs[:0]
				for _, x := range s.jobs {
					if x.ID != j.ID {
						nj = append(nj, x)
					}
				}
				s.jobs = nj
				s.jobsMu.Unlock()
				s.saveJobs()
			}
		}
	}
}

// verOlderThan reports whether v is a dotted version strictly older than
// min. Empty/unparseable versions return false (unknown, not required).
func verOlderThan(v, min string) bool {
	parse := func(s string) ([]int, bool) {
		var parts []int
		for _, p := range strings.Split(strings.TrimSpace(s), ".") {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return nil, false
			}
			parts = append(parts, n)
		}
		if len(parts) == 0 {
			return nil, false
		}
		return parts, true
	}
	a, ok1 := parse(v)
	b, ok2 := parse(min)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// Agents returns a snapshot for UI/API.
func (s *Server) Agents() []map[string]interface{} {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	out := make([]map[string]interface{}, 0, len(s.agents))
	for _, a := range s.agents {
		s.latencyMu.RLock()
		lat := s.latency[a.id]
		s.latencyMu.RUnlock()
		// Relay agents unseen for a while are reported offline (with
		// last-seen) rather than dropped, so the UI can gray them instead
		// of silently losing them. Restored inventory entries (direct ids
		// with no live conn) report offline the same way.
		online := true
		var seenAgo int64
		if strings.HasPrefix(a.id, "agent-ntfy-") || strings.HasPrefix(a.id, "agent-mqtt-") {
			ago := time.Since(a.seen())
			seenAgo = int64(ago.Seconds())
			online = ago <= relayStaleAfter
		} else if a.conn == nil {
			ago := time.Since(a.seen())
			seenAgo = int64(ago.Seconds())
			online = false
		}
		outdated := a.version != "" && a.version != version.DesktopAgentVersion
		// v1.45 removed ntfy and changed relay behavior: agents older
		// than 1.45.0 must update (their ntfy path is dead code).
		updateRequired := verOlderThan(a.version, "1.45.0")
		prot := a.prot
		rb, rt := a.rollbackBad, a.rollbackTo
		if rb == "" {
			s.holdMu.Lock()
			if cur, ok := s.heldBack[a.hostname]; ok {
				rb, rt = cur.Bad, cur.To
			}
			s.holdMu.Unlock()
		}
		s.groupsMu.Lock()
		grp := s.groups[a.id]
		s.groupsMu.Unlock()
		out = append(out, map[string]interface{}{
			"id": a.id, "hostname": a.hostname, "user": a.user,
			"version": a.version, "outdated": outdated,
			"updateRequired": updateRequired,
			"rollbackBad": rb, "rollbackTo": rt,
			"untrusted": a.untrusted, "prot": prot, "group": grp, "mode": a.mode,
			"connected": online, "seenAgoSec": seenAgo,
			"latency": lat, "remote": a.remote(), "e2e": s.e2eHas(a.id),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	return out
}

func (s *Server) setAgent(a *AgentConn) {
	s.agentsMu.Lock()
	a.touch()
	s.agents[a.id] = a
	if s.currentAgent == nil {
		s.currentAgent = a // stable selection: keep first, don't steal
	}
	s.agentsMu.Unlock()
	s.broadcastAgents()
}

func (s *Server) getAgent() *AgentConn {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	return s.currentAgent
}

func (s *Server) getAgentByID(id string) *AgentConn {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	if id == "" {
		return s.currentAgent
	}
	return s.agents[id]
}

// getMQTTAgent resolves a relay agent by the plain hostname its messages
// arrive under. Prefers the exact id (old agents without instance ids),
// then falls back to matching AgentConn.hostname so instanced
// (v1.4.6+) agents are found.
func (s *Server) getMQTTAgent(host string) *AgentConn {
	if host == "" {
		return nil
	}
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	if ac, ok := s.agents["agent-mqtt-"+host]; ok {
		return ac
	}
	for _, ac := range s.agents {
		if strings.HasPrefix(ac.id, "agent-mqtt-") && ac.hostname == host {
			return ac
		}
	}
	return nil
}

// findAgentByHostname returns any connected agent (any transport) with the
// given hostname, for stream-to-device mapping.
func (s *Server) findAgentByHostname(host string) *AgentConn {
	if host == "" {
		return nil
	}
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	for _, ac := range s.agents {
		if ac.hostname == host {
			return ac
		}
	}
	return nil
}

// handleAudioChunk plays one live PCM chunk from a streaming agent on the
// operator's selected local device (see audio_playback.go). Chunks arrive
// as {"seq":N,"data":"base64 s16 mono 22050Hz"}.
func (s *Server) handleAudioChunk(topic string, env relay.Envelope) {
	s.mqttLastMsg.Store(time.Now().UnixNano())
	host := strings.TrimPrefix(env.From, "agent:")
	if host == "" || host == env.From {
		if i := strings.LastIndex(topic, "/"); i != -1 {
			host = topic[i+1:]
		}
	}
	if host == "" {
		return
	}
	// Look up agent by hostname to get agent ID for E2E
	agentID := ""
	ac := s.getMQTTAgent(host)
	if ac != nil {
		agentID = ac.id
	} else {
		agentID = host // fallback for old agents without instance IDs
	}
	payload := env.Payload
	if env.Enc {
		plain, ok := s.e2eDecryptEnv(agentID, env)
		if !ok {
			return
		}
		payload = plain
	}
	var chunk struct {
		Seq  int    `json:"seq"`
		V    int    `json:"v"`
		K    bool   `json:"k"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(payload, &chunk); err != nil {
		return
	}
	wire, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil || len(wire) == 0 {
		return
	}
	s.ingestAudioChunk(host, chunk.Seq, chunk.K, chunk.V, wire)
}

// ingestAudioChunk is the shared tail for v1 JSON and v2 binary audio:
// lockstep guard, decode, player routing, write.
func (s *Server) ingestAudioChunk(host string, seq int, key bool, v int, wire []byte) {
	// Lockstep guard: keyframes and sequence gaps both reset the
	// predictor, bounding any divergence window. Gaps are counted.
	if noteAudioSeq(host, seq, key) {
		resetAudioDecoder(host)
	}
	raw := decodeAudioChunk(host, v, wire)
	if len(raw) == 0 {
		return
	}
	dev := ""
	gain := 1.0
	clarity := true
	m := cachedLocalAudioMap()
	if ac := s.findAgentByHostname(host); ac != nil {
		dev = choiceForAgent(m, ac.id)
		gain = float64(volumeForAgent(m, ac.id)) / 100
		clarity = clarityForAgent(m, ac.id)
	} else {
		dev = choiceForAgent(m, "")
		gain = float64(volumeForAgent(m, "")) / 100
		clarity = clarityForAgent(m, "")
	}
	if played, err := ensureAudioPlayer(host, dev, gain, clarity); err != nil {
		log.Printf("[audio] %s: player error: %v", host, err)
		s.broadcastWS(map[string]interface{}{"type": "output", "id": host, "data": "audio player: " + err.Error(), "success": false})
	} else if played != "" {
		s.broadcastWS(map[string]interface{}{"type": "output", "id": host, "data": "audio playing on [" + played + "]", "success": true})
	}
	writeAudioChunk(raw)
}

// handleAudioBin ingests binary v2 media frames from audiobin/<host>:
// ver(1) + frames of seq u32LE(4) + flags(1) + ADPCM(276), batched 1-2.
// ver 0x03 = sealed blob (nonce||ciphertext) opened with the host key.
// Legacy v1 JSON keeps flowing through audio/+ untouched.
func (s *Server) handleAudioBin(topic string, body []byte) {
	s.mqttLastMsg.Store(time.Now().UnixNano())
	host := topic[strings.LastIndex(topic, "/")+1:]
	if host == "" || len(body) < 1 {
		return
	}
	if body[0] == 0x03 {
		key, ok := s.e2eGet(host)
		if !ok {
			return
		}
		plain, err := relay.OpenRaw(key, body[1:])
		if err != nil {
			return
		}
		body = plain
	}
	const frameLen = 282 // 1 ver + 4 seq + 1 flags + 276 ADPCM
	for len(body) >= frameLen {
		f := body[:frameLen]
		if f[0] != 0x02 {
			return
		}
		seq := int(f[1]) | int(f[2])<<8 | int(f[3])<<16 | int(f[4])<<24
		s.ingestAudioChunk(host, seq, f[5]&1 == 1, 1, f[6:frameLen])
		body = body[frameLen:]
	}
}

// disconnectAgent ends the session with one agent WITHOUT touching the
// remote machine: it asks the agent to go quiet for a while, drops it from
// the visible list, and closes direct TCP conns. The agent service keeps
// running and resumes on its own (or instantly if the user selects it —
// see below). Power commands are never involved.
func (s *Server) disconnectAgent(id string) {
	ac := s.getAgentByID(id)
	if ac == nil {
		return
	}
	name, aid := ac.hostname, ac.id
	_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeDisconnect})
	if ac.conn != nil {
		conn := ac.conn
		go func() {
			time.Sleep(500 * time.Millisecond) // let the message flush
			conn.Close()
		}()
	}
	s.removeAgent(aid)
	fmt.Printf("\n[-] Disconnected %s (%s) — agent service keeps running, PC untouched\n> ", name, aid)
}

// supersededRow reports whether a same-hostname row is a stale duplicate
// of the confirmed (keepID, ver) process: different id, version that is
// not the confirmed one, and unseen past the relay-stale horizon. Live
// sibling transports (current version, or recently seen) never qualify.
func supersededRow(aid string, ac *AgentConn, keepID, hostname, ver string, now time.Time) bool {
	if aid == keepID || ac.hostname != hostname {
		return false
	}
	if ac.version == ver {
		return false
	}
	return now.Sub(ac.seen()) > relayStaleAfter
}

// evictSupersededDuplicates drops other records for the same hostname
// once one of them confirms the new version: the old rows are dead
// processes (killed by the update restart / singleton), kept only as
// tombstones. Only stale, version-mismatched rows go — a live sibling
// transport on the current version is never touched.
func (s *Server) evictSupersededDuplicates(hostname, keepID, ver string) {
	if hostname == "" || ver == "" {
		return
	}
	var dead []string
	s.agentsMu.RLock()
	now := time.Now()
	for aid, ac := range s.agents {
		if supersededRow(aid, ac, keepID, hostname, ver, now) {
			dead = append(dead, aid)
		}
	}
	s.agentsMu.RUnlock()
	for _, aid := range dead {
		log.Printf("[update] evicting stale duplicate %s (%s)", aid, hostname)
		s.removeAgent(aid)
	}
	if len(dead) > 0 {
		s.broadcastWS(map[string]interface{}{"type": "output", "id": keepID, "data": fmt.Sprintf("cleared %d stale duplicate row(s) for %s", len(dead), hostname), "success": true})
	}
}

func (s *Server) removeAgent(id string) {
	s.agentsMu.Lock()
	delete(s.agents, id)
	if s.currentAgent != nil && s.currentAgent.id == id {
		s.currentAgent = nil
		for _, v := range s.agents {
			s.currentAgent = v
			break
		}
	}
	s.agentsMu.Unlock()
	s.haveMu.Lock()
	delete(s.updateHave, id)
	s.haveMu.Unlock()
	s.saveInventory()
	s.broadcastAgents()
}

func (s *Server) broadcastAgents() {
	list := s.Agents()
	msg, _ := json.Marshal(map[string]interface{}{"type": "agents", "agents": list})
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for c := range s.wsClients {
		_ = c.writeMsg(msg)
	}
}

func (s *Server) broadcastWS(msg interface{}) {
	b, _ := json.Marshal(msg)
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for c := range s.wsClients {
		_ = c.writeMsg(b)
	}
}

// broadcastAudiolistIfJSON forwards list-audio-endpoints results to the UI
// device pickers. Returns true when result was endpoint JSON.
func (s *Server) broadcastAudiolistIfJSON(result, id string) bool {
	trimmed := strings.TrimSpace(result)
	if !strings.HasPrefix(trimmed, "[") {
		return false
	}
	var entries []struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil || len(entries) == 0 {
		return false
	}
	if entries[0].Name == "" || entries[0].Kind == "" {
		return false
	}
	s.broadcastWS(map[string]interface{}{"type": "audiolist", "id": id, "data": trimmed})
	return true
}

// sendToAgent routes via MQTT (directed) for virtual agents, TLS otherwise.
// Ntfy was removed in v1.45: any lingering agent-ntfy-* record is dead.
func (s *Server) sendToAgent(ac *AgentConn, msg protocol.Message) error {
	// Unique command id so agents drop duplicates when two controllers
	// deliver the same command (one fleet, several houses).
	if msg.Type == protocol.TypeCommand && msg.CmdID == "" {
		msg.CmdID = fmt.Sprintf("c%d-%d", s.idCounter.Add(1), time.Now().UnixNano())
	}
	if strings.HasPrefix(ac.id, "agent-ntfy-") {
		return fmt.Errorf("ntfy transport removed in v1.45 (agent %s must update to direct/MQTT)", ac.hostname)
	}
	if strings.HasPrefix(ac.id, "agent-mqtt-") {
		s.mqttMu.Lock()
		bus, bus2 := s.mqttBus, s.mqttBus2
		s.mqttMu.Unlock()
		if bus == nil && bus2 == nil {
			return fmt.Errorf("mqtt bus not connected")
		}
		host := ac.mqttHost()
		var env relay.Envelope
		if payload, enc := s.e2eSealMsg(ac.id, msg); enc {
			env = relay.Envelope{From: "controller", To: host, Payload: payload, Enc: true, Time: time.Now().UnixMilli()}
		} else {
			env = relay.Envelope{From: "controller", To: host, Payload: mustJSON(msg), Time: time.Now().UnixMilli()}
		}
		// Publish on both buses: the agent sits on one, so exactly one
		// copy ever arrives — but a primary-only publish vanishes when the
		// agent picked the other broker. Secondary goes async: publish
		// blocks up to 10s on a blackholed bus, and serial would double
		// worst-case command latency.
		//
		// Small interactive orders ride the 2s fast publish (a wedged hop
		// fails over in 2s, not 10s); bulk chunks keep 10s.
		pub := bus.PublishCmd
		switch msg.Type {
		case protocol.TypeScreenshotRequest, protocol.TypePing,
			protocol.TypeCommand, protocol.TypeFileDlReq,
			protocol.TypeUpdateBegin, protocol.TypeFileUlBegin:
			pub = bus.PublishCmdFast
		}
		s.trackCmd(msg, ac.id) // relay loss is real: retry if no output
		// Bulk chunks are idempotent (agent reassembles by seq) but huge:
		// dual-bus delivery doubles multi-MB pushes for zero gain, so
		// update/file chunks ride the primary bus only. Begins stay dual
		// (tiny, must not be missed).
		if msg.Type != protocol.TypeUpdateChunk && msg.Type != protocol.TypeFileUlChunk && bus2 != nil {
			go bus2.PublishCmd(host, env)
		}
		if bus != nil {
			return pub(host, env)
		}
		return nil
	}
	if err := ac.send(msg); err != nil {
	// Direct link died: fail over to the same host's MQTT relay record
	// instead of dropping the command.
		// CmdID dedupe on the agent makes double delivery harmless.
		if sib := s.siblingRelay(ac); sib != nil {
			log.Printf("[failover] %s direct failed (%v), retrying via %s", ac.hostname, err, sib.id)
			return s.sendToAgent(sib, msg)
		}
		return err
	}
	return nil
}

// siblingRelay finds another record for the same hostname on the MQTT
// relay, excluding the given record.
func (s *Server) siblingRelay(ac *AgentConn) *AgentConn {
	if ac == nil || ac.hostname == "" {
		return nil
	}
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	for _, v := range s.agents {
		if v == ac || v.hostname != ac.hostname {
			continue
		}
		if strings.HasPrefix(v.id, "agent-mqtt-") {
			return v
		}
	}
	return nil
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (s *Server) handleAgent(conn net.Conn, id string) {
	defer conn.Close()
	enc := json.NewEncoder(conn)
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), maxScannerBytes)

	if !scanner.Scan() {
		log.Printf("[%s] no connect message: %v", id, scanner.Err())
		return
	}
	var first protocol.Message
	if err := json.Unmarshal(scanner.Bytes(), &first); err != nil {
		log.Printf("[%s] bad connect json: %v", id, err)
		return
	}
	if first.Type != protocol.TypeConnect {
		log.Printf("[%s] expected connect, got %s", id, first.Type)
		return
	}
	allow, untrusted := s.checkAuth(first, id)
	if !allow {
		return
	}
	ac := &AgentConn{conn: conn, enc: enc, hostname: first.Hostname, user: first.User, id: id, version: first.Version, untrusted: untrusted, mode: first.Mode}
	s.setAgent(ac)
	if first.Version != "" && first.Version != version.DesktopAgentVersion {
		log.Printf("[update] %s is outdated (%s vs %s) — push update available", first.Hostname, first.Version, version.DesktopAgentVersion)
	}
	s.noteHello(id, first.Hostname, first.Version, first.RollbackBad, first.RollbackTo, first.Prot, first.ProtDetail, first.Mode)
	fmt.Printf("\n[+] Agent connected: id=%s hostname=%s user=%s version=%s mode=%s remote=%s\n", id, first.Hostname, first.User, first.Version, first.Mode, conn.RemoteAddr())
	_ = ac.send(protocol.Message{Type: protocol.TypeConnected, ID: id, RollbackAck: first.RollbackBad != ""})
	s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("Agent %s (%s) connected", first.Hostname, id), "success": true})

	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) == 0 {
			continue
		}
		var msg protocol.Message
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("[%s] bad json: %v raw=%.200s", id, err, string(line))
			continue
		}
		ac.touch()
		switch msg.Type {
		case protocol.TypeScreen:
			s.handleScreen(msg, id)
			s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq, "scale": msg.Scale})
		case protocol.TypeTile:
			// Changed tiles are never written to disk (keyframes still save
			// via TypeScreen); they stream straight to the UI compositor.
			s.broadcastWS(map[string]interface{}{"type": "tile", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq, "scale": msg.Scale})
		case protocol.TypeFileDlChunk:
			s.handleFileDlChunk(id, msg)
		case protocol.TypeMouse:
			s.broadcastWS(map[string]interface{}{"type": "mouse", "id": id, "x": msg.X, "y": msg.Y, "buttons": msg.Buttons})
		case protocol.TypeOutput:
			s.ackCmd(msg.CmdID)
			if isCamFragLine(msg.Result) {
				if url, ok := s.assembleCamFrag(id, msg.Result); ok {
					msg.Result = url
				} else {
					continue // more frags coming; already acked
				}
			}
			s.noteUpdateHave(id, msg.Result)
			s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": msg.Result, "error": msg.Error, "success": msg.Error == ""})
			if msg.Error == "" {
				s.broadcastAudiolistIfJSON(msg.Result, id)
			}
			if msg.Error != "" {
				fmt.Printf("\n[output:%s] ERROR: %s\n> ", id, msg.Error)
				continue
			}
			out := strings.TrimRight(msg.Result, "\r\n")
			if msg.Cmd != "" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(msg.Cmd)), "list-directory") {
				s.broadcastWS(map[string]interface{}{"type": "filelist", "isRemote": true, "data": msg.Result, "id": id})
			} else if strings.Contains(out, "\"entries\"") && strings.Contains(out, "\"path\"") {
				s.broadcastWS(map[string]interface{}{"type": "filelist", "isRemote": true, "data": out, "id": id})
			}
			fmt.Printf("\n[output:%s]\n%s\n> ", id, out)
		case protocol.TypeFileList:
			s.broadcastWS(map[string]interface{}{"type": "filelist", "isRemote": true, "data": msg.Result, "id": id})
		case protocol.TypePing:
			_ = ac.send(protocol.Message{Type: protocol.TypePong})
		case protocol.TypePong:
			ac.pingSentMu.Lock()
			sent := ac.pingSent
			ac.pingSentMu.Unlock()
			if !sent.IsZero() {
				s.latencyMu.Lock()
				s.latency[id] = time.Since(sent).Milliseconds()
				s.latencyMu.Unlock()
			}
			s.broadcastWS(map[string]interface{}{"type": "pong", "id": id})
		case protocol.TypeDisconnect:
			fmt.Printf("\n[-] Agent %s disconnecting\n> ", id)
			s.removeAgent(id)
			return
		default:
			fmt.Printf("\n[msg:%s] type=%s\n> ", id, msg.Type)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("\n[-] Agent %s read error: %v\n> ", id, err)
	} else {
		fmt.Printf("\n[-] Agent %s disconnected\n> ", id)
	}
	s.removeAgent(id)
	s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("Agent %s disconnected", id), "success": false})
}

// screenJob is one frame awaiting disk archival.
type screenJob struct {
	id  string
	msg protocol.Message
}

// handleScreen validates a frame and queues it for background disk
// archival. Decoding + mkdir + write + readdir on the hot path cost
// 5-15ms per frame at stream rates; the UI already got its copy via the
// broadcast at the call site, so the archive follows asynchronously. A
// full queue drops the save (best-effort archive, never blocks live view).
func (s *Server) handleScreen(msg protocol.Message, id string) {
	if msg.Data == "" {
		return
	}
	if len(msg.Data) > maxScreenBytes*4/3+1024 {
		fmt.Printf("\n[screen:%s] payload too large (%d chars), dropped\n> ", id, len(msg.Data))
		return
	}
	select {
	case s.screenSave <- screenJob{id: id, msg: msg}:
	default:
	}
}

// screenSaveLoop is the single background disk writer for frames.
func (s *Server) screenSaveLoop() {
	for {
		select {
		case <-s.closeCh:
			return
		case job := <-s.screenSave:
			s.saveScreenFrame(job.msg, job.id)
		}
	}
}

func (s *Server) saveScreenFrame(msg protocol.Message, id string) {
	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		fmt.Printf("\n[screen:%s] base64 decode error: %v\n> ", id, err)
		return
	}
	if len(data) > maxScreenBytes {
		fmt.Printf("\n[screen:%s] image too large (%d bytes), dropped\n> ", id, len(data))
		return
	}
	if err := os.MkdirAll(s.screenshotDir, 0755); err != nil {
		log.Printf("mkdir screenshots: %v", err)
		return
	}
	sid := s.screenshotN.Add(1)
	ext := msg.Format
	if ext != "jpeg" && ext != "jpg" && ext != "png" {
		ext = "png" // back-compat with old agents
	}
	if ext == "jpg" {
		ext = "jpeg"
	}
	fname := fmt.Sprintf("%s_%03d_%dx%d.%s", id, sid, msg.Width, msg.Height, ext)
	fpath := filepath.Join(s.screenshotDir, fname)
	if err := os.WriteFile(fpath, data, 0644); err != nil {
		fmt.Printf("\n[screen:%s] write error: %v\n> ", id, err)
		return
	}
	// Throttle directory rotation: a readdir+stat of the kept files on
	// EVERY frame is pure waste during a live stream. A missed rotate
	// only delays cleanup; the next one catches up.
	if now := time.Now().UnixNano(); now-s.lastScreenRotate.Swap(now) > 30e9 {
		s.rotateScreens()
	}
	fmt.Printf("\n[screen:%s] saved %s (%d bytes, %dx%d)\n> ", id, fpath, len(data), msg.Width, msg.Height)
}

// rotateScreens keeps the newest maxScreensKept files.
func (s *Server) rotateScreens() {
	entries, err := os.ReadDir(s.screenshotDir)
	if err != nil || len(entries) <= maxScreensKept {
		return
	}
	type fi struct {
		name string
		mod  time.Time
	}
	var files []fi
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fi{e.Name(), info.ModTime()})
	}
	if len(files) <= maxScreensKept {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	for _, f := range files[:len(files)-maxScreensKept] {
		_ = os.Remove(filepath.Join(s.screenshotDir, f.name))
	}
}

// tcpRelayLoop dials out to a TCP relay for NAT traversal (both sides dial out).
func (s *Server) tcpRelayLoop() {
	addrs := []string{"127.0.0.1:5590"}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
		}
		for _, raddr := range addrs {
			raw, err := net.DialTimeout("tcp", raddr, 3*time.Second)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(raw, "RELAY %s\n", "rmm-default"); err != nil {
				raw.Close()
				continue
			}
			tlsConn := tls.Client(raw, s.tlsCfg)
			_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
			if err := tlsConn.Handshake(); err != nil {
				raw.Close()
				continue
			}
			_ = tlsConn.SetDeadline(time.Time{})
			id := fmt.Sprintf("agent-relay-%d", s.idCounter.Add(1))
			log.Printf("[+] Relay connection %s via %s -> %s", raddr, tlsConn.RemoteAddr(), id)
			go s.handleAgent(tlsConn, id)
			break
		}
	}
}

// sweepLoop heartbeats relay agents (mqtt) unseen for relayStaleAfter.
func (s *Server) sweepLoop() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	ticks := 0
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
		}
		ticks++
		// Persist the fleet inventory every ~30s so a controller restart
		// keeps known agents visible (as offline, with last-seen) instead
		// of an empty list.
		if ticks%2 == 0 {
			s.saveInventory()
		}
		// No auto-eviction: quiet relay agents stay visible as offline
		// tombstones (with last-seen) forever — the UI prunes them only on
		// explicit user action (per-row forget / clear-offline). Silent
		// disappearance made live agents look dead.
		// Desired-update orphan sweep (hourly): a desired queue whose
		// hostname has no connected agent and no push attempt in 24h is a
		// renamed/retired box — drop it so re-push loops can't outlive it.
		if ticks%240 == 0 {
			s.sweepDesiredUpdates()
		}
		// Heartbeat: re-push the full agent list so any UI that missed an
		// event-driven push converges within 15s regardless.
		s.broadcastAgents()
		// Presence: announce this controller + expire quiet peers (90s).
		// Peer count = multi-controller HA visibility in the UI.
		s.publishPresence()
		s.sweepPeers()
	}
}

// ctrlPresence is a controller heartbeat on the presence topic.
type ctrlPresence struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Time     int64  `json:"time"`
}

type peerInfo struct {
	hostname string
	version  string
	seen     int64 // unixnano
}

func (s *Server) ctrlID() string {
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "ctrl"
	}
	return fmt.Sprintf("%s-%d", hn, os.Getpid())
}

func (s *Server) publishPresence() {
	s.mqttMu.Lock()
	bus, bus2 := s.mqttBus, s.mqttBus2
	s.mqttMu.Unlock()
	if bus == nil && bus2 == nil {
		return
	}
	hn, _ := os.Hostname()
	env := relay.Envelope{From: "controller:" + s.ctrlID(), To: "controllers", Payload: mustJSON(ctrlPresence{ID: s.ctrlID(), Hostname: hn, Version: version.Version, Time: time.Now().UnixMilli()}), Time: time.Now().UnixMilli()}
	if bus2 != nil {
		go bus2.PublishPresence(env)
	}
	if bus != nil {
		_ = bus.PublishPresence(env)
	}
}

func (s *Server) notePeer(p ctrlPresence) {
	if p.ID == "" || p.ID == s.ctrlID() {
		return
	}
	s.peersMu.Lock()
	if s.peers == nil {
		s.peers = map[string]peerInfo{}
	}
	s.peers[p.ID] = peerInfo{hostname: p.Hostname, version: p.Version, seen: time.Now().UnixNano()}
	s.peersMu.Unlock()
}

func (s *Server) sweepPeers() {
	cut := time.Now().Add(-90 * time.Second).UnixNano()
	s.peersMu.Lock()
	for id, p := range s.peers {
		if p.seen < cut {
			delete(s.peers, id)
		}
	}
	s.peersMu.Unlock()
}

// peerCount reports live peer controllers (excluding self).
func (s *Server) peerCount() int {
	s.peersMu.Lock()
	defer s.peersMu.Unlock()
	return len(s.peers)
}

// mqttLoop keeps TWO MQTT buses on DIFFERENT brokers (primary + secondary
// listener) and routes inbound agent messages. Listening on both kills
// split-brain: agents are heard no matter which broker they picked, and
// outbound publishes go out on both (the agent sits on one, so exactly one
// copy ever arrives). paho auto-reconnects transient drops; per-bus
// watchdogs re-dial silent buses (blackhole without TCP close). Heartbeats
// land every ~15s, so 90s of silence means a dead bus, not a quiet one.
//
// Periodic re-SUBSCRIBE (every ~60s) forces the broker to re-establish
// subscriptions, healing silent broker-side subscription drops without
// requiring a full reconnect (which paho's ResumeSubs only covers on TCP
// disconnect/reconnect).
// subscribePrimaryBus registers hello + outputs + audio on a primary bus.
// Shared by mqttLoop (initial dial) and resubscribeMQTT (periodic heal) so
// both paths install identical callbacks and timestamp stores.
func (s *Server) subscribePrimaryBus(nb *mqttrelay.CtrlBus) error {
	if err := nb.Subscribe(func(topic string, env relay.Envelope) {
		s.mqttLastMsg1.Store(time.Now().UnixNano())
		s.handleMQTTMsg(topic, env)
	}); err != nil {
		return err
	}
	// Binary audio is best-effort: a failure here only loses audiobin
	// on this bus (JSON audio still flows).
	if err := nb.SubscribeBin(func(topic string, body []byte) {
		s.mqttLastMsg1.Store(time.Now().UnixNano())
		s.handleAudioBin(topic, body)
	}); err != nil {
		log.Printf("[mqtt] subscribe audiobin: %v", err)
	}
	return nil
}

// subscribeSecondaryBus is the secondary-bus twin (msg2 timestamp store).
func (s *Server) subscribeSecondaryBus(nb *mqttrelay.CtrlBus) error {
	if err := nb.Subscribe(func(topic string, env relay.Envelope) {
		s.mqttLastMsg2.Store(time.Now().UnixNano())
		s.handleMQTTMsg(topic, env)
	}); err != nil {
		return err
	}
	if err := nb.SubscribeBin(func(topic string, body []byte) {
		s.mqttLastMsg2.Store(time.Now().UnixNano())
		s.handleAudioBin(topic, body)
	}); err != nil {
		log.Printf("[mqtt] secondary subscribe audiobin: %v", err)
	}
	return nil
}

func (s *Server) mqttLoop() {
	watch := time.NewTicker(20 * time.Second)
	defer watch.Stop()
	resubTicker := time.NewTicker(60 * time.Second)
	defer resubTicker.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-resubTicker.C:
			s.resubscribeMQTT()
		default:
		}
		s.mqttMu.Lock()
		bus, bus2 := s.mqttBus, s.mqttBus2
		s.mqttMu.Unlock()
		if bus == nil {
			nb, err := mqttrelay.DialController()
			if err != nil {
				log.Printf("[mqtt] dial: %v", err)
				select {
				case <-s.closeCh:
					return
				case <-time.After(10 * time.Second):
				}
				continue
			}
		if err := s.subscribePrimaryBus(nb); err != nil {
			log.Printf("[mqtt] subscribe: %v", err)
			nb.Close()
			select {
			case <-s.closeCh:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		s.mqttMu.Lock()
		s.mqttBus = nb
		s.mqttMu.Unlock()
		s.mqttLastMsg.Store(time.Now().UnixNano())
		s.mqttLastMsg1.Store(time.Now().UnixNano())
		log.Printf("[mqtt] subscribed (hello, out/+, audio/+) via %s", nb.Broker())
		continue
		}
		if bus2 == nil {
			// Secondary listener on a different broker. Failure is routine
			// (only 3 brokers configured) — silent retry next round.
			if nb2, err := mqttrelay.DialControllerExcept(bus.Broker()); err == nil {
				if err := s.subscribeSecondaryBus(nb2); err != nil {
					nb2.Close()
				} else {
					s.mqttMu.Lock()
					// Re-check: primary may have rotated while we dialed.
					if s.mqttBus != nil && s.mqttBus.Broker() != nb2.Broker() {
						s.mqttBus2 = nb2
						s.mqttMu.Unlock()
						s.mqttLastMsg2.Store(time.Now().UnixNano())
						log.Printf("[mqtt] secondary subscribed via %s", nb2.Broker())
					} else {
						s.mqttMu.Unlock()
						nb2.Close()
					}
				}
			}
		} else if bus.Broker() == bus2.Broker() {
			// Converged on one broker (rotation race): secondary is pure
			// duplicate delivery — drop it, it redials elsewhere.
			log.Printf("[mqtt] secondary converged on %s, dropping", bus2.Broker())
			s.mqttMu.Lock()
			s.mqttBus2 = nil
			s.mqttMu.Unlock()
			bus2.Close()
		}
		// Watchdogs: silent bus + live MQTT agents = suspected blackhole.
		select {
		case <-s.closeCh:
			return
		case <-watch.C:
		}
		if time.Since(time.Unix(0, s.mqttLastMsg1.Load())) > 90*time.Second && s.hasMQTTAgents() {
			log.Printf("[mqtt] primary silent with live agents, re-dialing")
			s.mqttMu.Lock()
			s.mqttBus = nil
			s.mqttMu.Unlock()
			bus.Close()
		}
		s.mqttMu.Lock()
		b2 := s.mqttBus2
		s.mqttMu.Unlock()
		if b2 != nil && time.Since(time.Unix(0, s.mqttLastMsg2.Load())) > 90*time.Second && s.hasMQTTAgents() {
			log.Printf("[mqtt] secondary silent with live agents, re-dialing")
			s.mqttMu.Lock()
			s.mqttBus2 = nil
			s.mqttMu.Unlock()
			b2.Close()
		}
	}
}

func (s *Server) hasMQTTAgents() bool {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	for id := range s.agents {
		if strings.HasPrefix(id, "agent-mqtt-") {
			return true
		}
	}
	return false
}

// resubscribeMQTT forces re-subscription on both MQTT buses to heal
// silent broker-side subscription drops (broker loses subs without TCP close).
// paho's ResumeSubs only resubscribes on reconnect; this covers the case
// where the connection stays up but the broker forgets our subscriptions.
// Uses the same subscribe methods as the initial dial so both paths stay
// identical. A bus that refuses re-subscribe is dropped outright so the
// next loop pass re-dials it at once (instead of waiting out the 90s
// silence watchdog on a bus that can no longer hear anything).
func (s *Server) resubscribeMQTT() {
	s.mqttMu.Lock()
	bus, bus2 := s.mqttBus, s.mqttBus2
	s.mqttMu.Unlock()
	if bus != nil {
		if err := s.subscribePrimaryBus(bus); err != nil {
			log.Printf("[mqtt] resubscribe primary failed (%v), dropping bus", err)
			s.mqttMu.Lock()
			if s.mqttBus == bus {
				s.mqttBus = nil
			}
			s.mqttMu.Unlock()
			bus.Close()
		} else {
			log.Printf("[mqtt] periodic re-subscribe ok via %s", bus.Broker())
		}
	}
	if bus2 != nil {
		if err := s.subscribeSecondaryBus(bus2); err != nil {
			log.Printf("[mqtt] resubscribe secondary failed (%v), dropping bus", err)
			s.mqttMu.Lock()
			if s.mqttBus2 == bus2 {
				s.mqttBus2 = nil
			}
			s.mqttMu.Unlock()
			bus2.Close()
		} else {
			log.Printf("[mqtt] periodic secondary re-subscribe ok via %s", bus2.Broker())
		}
	}
}

func (s *Server) handleMQTTMsg(topic string, env relay.Envelope) {
	s.mqttLastMsg.Store(time.Now().UnixNano())
	// Controller presence (plaintext id/hostname/version only — no agent
	// data, nothing sensitive; agents never subscribe to this topic).
	if strings.HasSuffix(topic, "/presence") {
		var p ctrlPresence
		if err := json.Unmarshal(env.Payload, &p); err == nil {
			s.notePeer(p)
		}
		return
	}
	// Decrypt first (hostname available from From/topic without plaintext).
	hostHint := strings.TrimPrefix(env.From, "agent:")
	if hostHint == "" || hostHint == env.From {
		if i := strings.LastIndex(topic, "/"); i != -1 {
			hostHint = topic[i+1:]
		}
	}
	// Determine agent ID for E2E: try to look up by hostname, fall back to hostname
	agentID := hostHint
	if ac := s.getMQTTAgent(hostHint); ac != nil {
		agentID = ac.id
	}
	payload := env.Payload
	if env.Enc {
		plain, ok := s.e2eDecryptEnv(agentID, env)
		if !ok {
			return
		}
		payload = plain
	}
	var msg protocol.Message
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	// Key exchange precedes registration (no agent entry needed).
	// Use instance from message to construct agent ID for per-instance keys.
	if msg.Type == protocol.TypeKeyExchange {
		inst := msg.Instance
		if inst == "" {
			inst = hostHint // old agents without instance ids
		}
		keyAgentID := "agent-mqtt-" + inst
		s.e2eKeyxchg(keyAgentID, msg.Data)
		return
	}
	if strings.HasSuffix(topic, "/hello") {
		if msg.Type != protocol.TypeConnect {
			return
		}
		host := msg.Hostname
		if host == "" {
			host = strings.TrimPrefix(env.From, "agent:")
		}
		inst := msg.Instance
		if inst == "" {
			inst = host // old agents without instance ids
		}
		id := "agent-mqtt-" + inst
		allow, untrusted := s.checkAuth(msg, id)
		if !allow {
			return
		}
		s.agentsMu.RLock()
		_, exists := s.agents[id]
		s.agentsMu.RUnlock()
		// Stash version from hello ("" = old agent, unknown).
		s.agentsMu.Lock()
		if existing, ok := s.agents[id]; ok && msg.Version != "" {
			existing.version = msg.Version
		}
		s.agentsMu.Unlock()
		if !exists {
			ac := &AgentConn{hostname: host, user: msg.User, id: id, version: msg.Version, untrusted: untrusted, mode: msg.Mode}
			s.setAgent(ac)
			fmt.Printf("\n[+] MQTT agent connected: %s (%s) v%s\n", host, id, msg.Version)
			s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("MQTT agent %s connected", host), "success": true})
		}
		// Ack every hello (not just first-seen): agents gate outbound
		// encryption on an ack carrying the E2E flag, and re-acks heal
		// controller restarts without waiting for reconnects. Ack goes on
		// both buses: the agent sits on one, so exactly one copy arrives.
		s.mqttMu.Lock()
		bus, bus2 := s.mqttBus, s.mqttBus2
		s.mqttMu.Unlock()
		ack := relay.Envelope{From: "controller", To: host, Payload: mustJSON(protocol.Message{Type: protocol.TypeConnected, ID: id, E2E: true, RollbackAck: msg.RollbackBad != ""}), Time: time.Now().UnixMilli()}
		if bus2 != nil {
			go bus2.PublishCmd(host, ack)
		}
		if bus != nil {
			_ = bus.PublishCmd(host, ack)
		}
		// Re-announce of a known agent: refresh lastSeen + version so the
		// outdated badge stays accurate after an agent self-updates.
		if ac := s.getAgentByID(id); ac != nil {
			ac.touch()
			if msg.Version != "" {
				ac.version = msg.Version
			}
			if msg.Mode != "" {
				ac.mode = msg.Mode
			}
		}
		s.noteHello(id, host, msg.Version, msg.RollbackBad, msg.RollbackTo, msg.Prot, msg.ProtDetail, msg.Mode)
		s.broadcastAgents()
		return
	}
	// audio/<host>: live PCM chunks (see internal/commands audio_stream.go).
	if strings.Contains(topic, "/audio/") {
		s.handleAudioChunk(topic, env)
		return
	}
	// out/<host>
	host := strings.TrimPrefix(env.From, "agent:")
	if host == "" || host == env.From {
		// fall back to topic suffix
		if i := strings.LastIndex(topic, "/"); i != -1 {
			host = topic[i+1:]
		}
	}
	// Agents publish from their plain hostname, but since v1.4.6 the
	// registered id carries the unique instance (agent-mqtt-<host>-<pid>).
	// An exact-id lookup misses every time and outputs/screens were
	// silently dropped. Resolve by hostname.
	ac := s.getMQTTAgent(host)
	if ac == nil {
		return
	}
	id := ac.id
	ac.touch()
	switch msg.Type {
			case protocol.TypeOutput:
				s.ackCmd(msg.CmdID)
				if isCamFragLine(msg.Result) {
					if url, ok := s.assembleCamFrag(id, msg.Result); ok {
						msg.Result = url
					} else {
						return // more frags coming; already acked
					}
				}
				s.noteUpdateHave(id, msg.Result)
				s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": msg.Result, "error": msg.Error, "success": msg.Error == ""})
				if msg.Error == "" {
					s.broadcastAudiolistIfJSON(msg.Result, id)
				}
				if strings.Contains(msg.Result, "\"entries\"") && strings.Contains(msg.Result, "\"path\"") {
					s.broadcastWS(map[string]interface{}{"type": "filelist", "isRemote": true, "data": msg.Result, "id": id})
				}
				fmt.Printf("\n[mqtt output:%s]\n%s\n> ", host, msg.Result)
  	case protocol.TypeScreen:
  		s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq, "scale": msg.Scale})
  		s.handleScreen(msg, id)
  	case protocol.TypeTile:
  		s.broadcastWS(map[string]interface{}{"type": "tile", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq, "scale": msg.Scale})
  	case protocol.TypeFileDlChunk:
  		s.handleFileDlChunk(id, msg)
 	case protocol.TypeMouse:
		s.broadcastWS(map[string]interface{}{"type": "mouse", "id": id, "x": msg.X, "y": msg.Y})
	case protocol.TypePong:
		ac.pingSentMu.Lock()
		sent := ac.pingSent
		ac.pingSentMu.Unlock()
		if !sent.IsZero() {
			s.latencyMu.Lock()
			s.latency[id] = time.Since(sent).Milliseconds()
			s.latencyMu.Unlock()
		}
		s.broadcastWS(map[string]interface{}{"type": "pong", "id": id})
	}
}

func resolveCert(p, base string) string {
	if p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, c := range []string{filepath.Join(exeDir, base), filepath.Join(exeDir, "certs", base)} {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	if p != "" {
		return p
	}
	return base
}

func resolveScreensDir(dir string) string {
	if dir == "" {
		dir = "screenshots"
	}
	if err := os.MkdirAll(dir, 0755); err == nil {
		return dir
	}
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		fb := filepath.Join(localApp, "RMM", "screenshots")
		if err := os.MkdirAll(fb, 0755); err == nil {
			fmt.Printf("[!] Screens dir not writable, using %s\n", fb)
			return fb
		}
	}
	fb := filepath.Join(os.TempDir(), "RMM", "screenshots")
	_ = os.MkdirAll(fb, 0755)
	return fb
}

// OpenBrowser opens url in the system browser.
func OpenBrowser(url string) { openBrowser(url) }

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}


