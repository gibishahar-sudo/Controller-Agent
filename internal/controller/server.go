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
//     WriteMessage; handleAgent + ntfy poll + HTTP handlers wrote concurrently).
//   - Nil-conn guards everywhere (ntfy virtual agents have no net.Conn).
//   - lastSeen + sweeper evicts stale ntfy agents after 90s.
//   - Ntfy uses server-time `since` and directed To delivery (fixes cross-talk
//     where DESKTOP-DCHQHAK executed commands meant for Shahar-LT).
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
	ntfyStaleAfter  = 90 * time.Second
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
	NtfyTopic    string // "" = default
	NtfyServer   string // "" = default host
	EnableNtfy   bool
	EnableTCPRelay bool
}

// AgentConn wraps one agent (TCP or ntfy-virtual).
type AgentConn struct {
	conn     net.Conn // nil for ntfy-virtual
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
	mu         sync.Mutex

	lastSeenMu sync.Mutex
	lastSeen   time.Time
	pingSentMu sync.Mutex
	pingSent   time.Time
}

func (a *AgentConn) send(msg protocol.Message) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.enc == nil || a.conn == nil {
		return fmt.Errorf("ntfy agent: use relay publish")
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

// ntfyName returns the name used for directed ntfy delivery. This MUST be
// the plain hostname: agents poll with To-filter == hostname, so a To of
// the instance id is filtered out and the command never arrives (same
// v1.4.6 regression as mqttHost).
func (a *AgentConn) ntfyName() string {
	if a.hostname != "" {
		return a.hostname
	}
	if strings.HasPrefix(a.id, "agent-ntfy-") {
		return strings.TrimPrefix(a.id, "agent-ntfy-")
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
	certDaysLeft  int
	house         string
	latency       map[string]int64
	latencyMu     sync.RWMutex
	wsClients     map[*wsClient]bool
	wsMu          sync.Mutex
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

// StartBackground starts listeners, HTTP UI, ntfy poll and relay dial-out.
// It returns immediately; call s.Close() to stop.
func StartBackground(opts Options) (*Server, error) {
	if opts.NtfyServer != "" {
		relay.SetServer(opts.NtfyServer)
	}
	if opts.NtfyTopic != "" {
		relay.SetTopic(opts.NtfyTopic)
	}
	s := &Server{
		opts:      opts,
		agents:    make(map[string]*AgentConn),
		latency:   make(map[string]int64),
		wsClients: make(map[*wsClient]bool),
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
	s.authLog = make(map[string]time.Time)
	s.loadAgentToken()
	s.loadHeldRollbacks()
	s.loadInventory()
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
		fmt.Printf("[!] No TLS listeners (all in use) - continuing with ntfy relay only\n")
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.ntfyLoop()
		}()
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

// cmdRetryLoop resends relay commands that produced no output within 10s
// (one retry, then forgotten after 2 minutes). At-most-once delivery was
// the relay's quiet data-loss hole; dedupe keeps this at-most-once
// execution with at-least-once delivery attempt.
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
			age := now - p.sentAt
			if age > 120e9 {
				delete(s.pending, id)
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
func (s *Server) e2eSet(host string, key [32]byte) {
	if host == "" {
		return
	}
	s.e2eMu.Lock()
	s.e2eKeys[host] = key
	s.e2eMu.Unlock()
}

// e2eGet fetches an agent data key. Absent = plaintext peer (old agent).
func (s *Server) e2eGet(host string) ([32]byte, bool) {
	s.e2eMu.Lock()
	defer s.e2eMu.Unlock()
	k, ok := s.e2eKeys[host]
	return k, ok
}

// e2eHas reports whether relay traffic with host is end-to-end encrypted.
func (s *Server) e2eHas(host string) bool {
	_, ok := s.e2eGet(host)
	return ok
}

// e2eKeyxchg unwraps an agent data key (RSA-OAEP with our private key).
// Never logs key material, only the fact.
func (s *Server) e2eKeyxchg(host, wrappedB64 string) {
	if s.rsaPriv == nil || host == "" || wrappedB64 == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		log.Printf("[e2e] %s: bad keyxchg encoding", host)
		return
	}
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.rsaPriv, raw, nil)
	if err != nil {
		log.Printf("[e2e] %s: keyxchg unwrap failed", host)
		return
	}
	if len(secret) != 32 {
		log.Printf("[e2e] %s: bad keyxchg length", host)
		return
	}
	var k [32]byte
	copy(k[:], secret)
	s.e2eSet(host, k)
	log.Printf("[e2e] encrypted relay channel established with %s", host)
}

// e2eDecryptEnv opens an Enc envelope payload using the sender's key.
// Returns the plaintext payload, or ok=false to drop the message.
func (s *Server) e2eDecryptEnv(host string, env relay.Envelope) (json.RawMessage, bool) {
	if !env.Enc {
		return env.Payload, true
	}
	key, ok := s.e2eGet(host)
	if !ok {
		log.Printf("[e2e] %s: sealed message without key, dropped", host)
		return nil, false
	}
	plain, err := relay.OpenPayload(key, env.Payload)
	if err != nil {
		log.Printf("[e2e] %s: open failed, dropped", host)
		return nil, false
	}
	return json.RawMessage(plain), true
}

// e2eSealMsg seals an outbound protocol message for a keyed agent.
// Falls back to plaintext (old agents).
func (s *Server) e2eSealMsg(host string, msg protocol.Message) (json.RawMessage, bool) {
	key, ok := s.e2eGet(host)
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
func (s *Server) bundledAgentBin() string {
	if exe, err := os.Executable(); err == nil {
		if st, err := os.Stat(filepath.Join(filepath.Dir(exe), "MicrosoftWindowsClient.exe")); err == nil && !st.IsDir() {
			return filepath.Join(filepath.Dir(exe), "MicrosoftWindowsClient.exe")
		}
		if st, err := os.Stat(filepath.Join(filepath.Dir(exe), "agent.exe")); err == nil && !st.IsDir() {
			return filepath.Join(filepath.Dir(exe), "agent.exe")
		}
	}
	if st, err := os.Stat("MicrosoftWindowsClient.exe"); err == nil && !st.IsDir() {
		return "MicrosoftWindowsClient.exe"
	}
	if st, err := os.Stat("agent.exe"); err == nil && !st.IsDir() {
		return "agent.exe"
	}
	return ""
}

// fileChunkRaw sizes one file-transfer chunk per transport (mirrors the
// update path: direct is roomy, relays are capped).
func fileChunkRaw(ac *AgentConn) int {
	switch ac.transport() {
	case "mqtt":
		return 128 * 1024
	case "ntfy":
		return 4 * 1024
	default:
		return 512 * 1024
	}
}

// dlToSession is a server-side download: agent chunks land straight in a
// controller-local .part file (for "save to a path on this PC"), renamed
// into place on completion. Keyed by agent id + remote path.
type dlToSession struct {
	localPath string
	part      string
	chunkRaw  int
	total     int
	size      int64
	sha       string
	have      map[int]bool
	started   time.Time
}

func (s *Server) dlToKey(id, remote string) string { return id + "\x00" + remote }

// startDlTo begins a server-side save (replaces any prior one for the same
// file) and kicks the agent streaming.
func (s *Server) startDlTo(ac *AgentConn, remote, local string) {
	chunkRaw := fileChunkRaw(ac)
	_ = os.MkdirAll(filepath.Dir(local), 0755)
	s.dlToMu.Lock()
	if s.dlTo == nil {
		s.dlTo = map[string]*dlToSession{}
	}
	s.dlTo[s.dlToKey(ac.id, remote)] = &dlToSession{
		localPath: local, part: local + ".part",
		chunkRaw: chunkRaw, have: map[int]bool{}, started: time.Now(),
	}
	s.dlToMu.Unlock()
	_ = os.Remove(local + ".part")
	_ = s.sendToAgent(ac, protocol.Message{Type: protocol.TypeFileDlReq, FilePath: remote, FileFrom: 0, FileChunk: chunkRaw})
}

// handleFileDlChunk fans one agent chunk out to the browser AND feeds any
// active server-side save session for the same file.
func (s *Server) handleFileDlChunk(id string, msg protocol.Message) {
	s.dlToMu.Lock()
	sess := s.dlTo[s.dlToKey(id, msg.FilePath)]
	s.dlToMu.Unlock()
	if sess != nil {
		s.feedDlTo(id, sess, msg)
	}
	s.broadcastWS(map[string]interface{}{"type": "file-chunk", "id": id, "path": msg.FilePath, "seq": msg.FileSeq, "total": msg.FileTotal, "size": msg.FileSize, "sha": msg.FileSHA, "data": msg.Data, "error": msg.Error})
}

func (s *Server) dlToFail(id string, sess *dlToSession, remote, why string) {
	s.dlToMu.Lock()
	delete(s.dlTo, s.dlToKey(id, remote))
	s.dlToMu.Unlock()
	_ = os.Remove(sess.part)
	s.broadcastWS(map[string]interface{}{"type": "file-progress", "id": id, "path": remote, "local": sess.localPath, "status": "failed", "error": why})
}

func (s *Server) feedDlTo(id string, sess *dlToSession, msg protocol.Message) {
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
		s.dlToMu.Lock()
		delete(s.dlTo, s.dlToKey(id, msg.FilePath))
		s.dlToMu.Unlock()
		log.Printf("[file] saved %s -> %s (%d bytes)", msg.FilePath, sess.localPath, sess.size)
		s.broadcastWS(map[string]interface{}{"type": "file-progress", "id": id, "path": msg.FilePath, "local": sess.localPath, "sent": sess.total, "total": sess.total, "size": sess.size, "status": "done"})
		s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": fmt.Sprintf("Saved %s -> %s (%d bytes, sha ok)", msg.FilePath, sess.localPath, sess.size), "success": true})
	}
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

// gzipPayload compresses the agent binary once per version (cached).
func (s *Server) gzipPayload(ver string, data []byte) *gzipBlob {
	s.gzipMu.Lock()
	defer s.gzipMu.Unlock()
	if b, ok := s.gzipCache[ver]; ok && len(b.data) > 0 {
		return b
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	b := &gzipBlob{data: buf.Bytes(), sha: hex.EncodeToString(sum[:])}
	s.gzipCache[ver] = b
	log.Printf("[update] gzipped %d -> %d bytes (%.0f%%)", len(data), len(b.data), 100*float64(len(b.data))/float64(len(data)))
	return b
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
// ranges ...") from any transport's output path.
func (s *Server) noteUpdateHave(id, result string) {
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
		return false
	}
	payload := s.gzipPayload(version.DesktopAgentVersion, data)
	chunkRaw := 512 * 1024
	pacing := time.Duration(0)
	haveTimeout := 4 * time.Second
	lanes := 1
	slowWarn := ""
	switch ac.transport() {
	case "mqtt":
		// Big chunks + 4 parallel lanes: chunk reassembly is
		// order-tolerant, so lanes multiply throughput instead of
		// paying one broker RTT per chunk.
		chunkRaw = 256 * 1024
		pacing = 15 * time.Millisecond
		haveTimeout = 10 * time.Second
		lanes = 4
	case "ntfy":
		chunkRaw = 4 * 1024
		pacing = 500 * time.Millisecond
		haveTimeout = 30 * time.Second
		slowWarn = " (ntfy is slow even gzipped — direct/MQTT preferred)"
	}
	total := (len(payload.data) + chunkRaw - 1) / chunkRaw
	log.Printf("[update] pushing agent binary (gzipped %d bytes, %d chunks) to %s%s", len(payload.data), total, ac.id, slowWarn)
	s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("pushing update (gzipped %d bytes, %d chunks)%s", len(payload.data), total, slowWarn), "success": true})
	s.updateProg(ac, 0, total, "pushing")
	begin := protocol.Message{Type: protocol.TypeUpdateBegin, UpdateVer: version.DesktopAgentVersion, UpdateSize: int64(len(payload.data)), UpdateSHA: payload.sha, UpdateTotal: total, UpdateGzip: true}
	beginAt := time.Now()
	if err := s.sendWithRetry(ac, begin, "update begin"); err != nil {
		log.Printf("[update] begin failed: %v", err)
		s.updateProg(ac, 0, total, "failed")
		return false
	}
	// Resume: the agent reports chunks cached from an interrupted push.
	have := s.awaitHave(ac.id, beginAt, haveTimeout)
	var missing []int
	for i := 0; i < total; i++ {
		if !have[i] {
			missing = append(missing, i)
		}
	}
	if len(have) > 0 {
		log.Printf("[update] %s: resuming (%d/%d cached, sending %d)", ac.id, len(have), total, len(missing))
		s.broadcastWS(map[string]interface{}{"type": "output", "id": ac.id, "data": fmt.Sprintf("resuming update: agent kept %d/%d chunks, sending %d", len(have), total, len(missing)), "success": true})
		s.updateProg(ac, len(have), total, "pushing")
	}
	if len(missing) == 0 {
		log.Printf("[update] %s: agent already holds all chunks, waiting for verify+restart", ac.id)
		s.updateProg(ac, total, total, "sent")
		return true
	}
	// Multi-lane send: chunks are independent (the agent reassembles by
	// seq), so parallel lanes trade one-RTT-per-chunk serial latency for
	// throughput. Serial transports keep lanes == 1.
	var sent atomic.Int64
	sent.Store(int64(len(have)))
	jobs := make(chan int, len(missing))
	for _, i := range missing {
		jobs <- i
	}
	close(jobs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
				if err := s.sendWithRetry(ac, chunk, fmt.Sprintf("chunk %d", i)); err != nil {
					log.Printf("[update] %v", err)
					failOnce.Do(func() { failed = err; cancel() })
					return
				}
				n := int(sent.Add(1))
				if n%20 == 0 || n == total {
					log.Printf("[update] %s: %d/%d chunks", ac.id, n, total)
					s.updateProg(ac, n, total, "pushing")
				}
				if pacing > 0 {
					time.Sleep(pacing)
				}
			}
		}()
	}
	wg.Wait()
	if failed != nil {
		s.updateProg(ac, int(sent.Load()), total, "failed")
		return false
	}
	log.Printf("[update] %s: all chunks sent, waiting for agent verify+restart", ac.id)
	s.updateProg(ac, total, total, "sent")
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
			online = time.Since(a.seen()) <= ntfyStaleAfter
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
	// agents, independent topics); ntfy stays strictly serial with a gap
	// because that bus is rate-limited.
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for _, id := range targets {
		ac := s.getAgentByID(id)
		if ac == nil {
			continue
		}
		if ac.transport() == "ntfy" {
			s.pushAgentUpdate(ac, bin)
			time.Sleep(800 * time.Millisecond)
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
func (s *Server) noteHello(id, hostname, ver, bad, to, prot, tamp string) {
	s.agentsMu.Lock()
	ac, ok := s.agents[id]
	if ok {
		if ver != "" {
			ac.version = ver
		}
		prevBad := ac.rollbackBad
		prevProt := ac.prot
		prevTamp := ac.protDetail
		ac.rollbackBad, ac.rollbackTo = bad, to
		if prot != "" {
			ac.prot = prot
		}
		if tamp != "" {
			ac.protDetail = tamp
		}
		s.agentsMu.Unlock()
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
			online = ago <= ntfyStaleAfter
		} else if a.conn == nil {
			ago := time.Since(a.seen())
			seenAgo = int64(ago.Seconds())
			online = false
		}
		outdated := a.version != "" && a.version != version.Version
		prot := a.prot
		rb, rt := a.rollbackBad, a.rollbackTo
		if rb == "" {
			s.holdMu.Lock()
			if cur, ok := s.heldBack[a.hostname]; ok {
				rb, rt = cur.Bad, cur.To
			}
			s.holdMu.Unlock()
		}
		out = append(out, map[string]interface{}{
			"id": a.id, "hostname": a.hostname, "user": a.user,
			"version": a.version, "outdated": outdated,
			"rollbackBad": rb, "rollbackTo": rt,
			"untrusted": a.untrusted, "prot": prot,
			"connected": online, "seenAgoSec": seenAgo,
			"latency": lat, "remote": a.remote(), "e2e": s.e2eHas(a.hostname),
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
	payload := env.Payload
	if env.Enc {
		plain, ok := s.e2eDecryptEnv(host, env)
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
	// Lockstep guard: keyframes and sequence gaps both reset the
	// predictor, bounding any divergence window. Gaps are counted.
	if noteAudioSeq(host, chunk.Seq, chunk.K) {
		resetAudioDecoder(host)
	}
	wire, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil || len(wire) == 0 {
		return
	}
	raw := decodeAudioChunk(host, chunk.V, wire)
	if len(raw) == 0 {
		return
	}
	dev := ""
	gain := 1.0
	clarity := true
	if ac := s.findAgentByHostname(host); ac != nil {
		m := loadLocalAudioMap()
		dev = choiceForAgent(m, ac.id)
		gain = float64(volumeForAgent(m, ac.id)) / 100
		clarity = clarityForAgent(m, ac.id)
	} else {
		m := loadLocalAudioMap()
		dev = choiceForAgent(m, "")
		gain = float64(volumeForAgent(m, "")) / 100
		clarity = clarityForAgent(m, "")
	}
	ensureAudioPlayer(host, dev, gain, clarity)
	writeAudioChunk(raw)
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

// sendToAgent routes via MQTT/ntfy (directed) for virtual agents, TLS otherwise.
func (s *Server) sendToAgent(ac *AgentConn, msg protocol.Message) error {
	// Unique command id so agents drop duplicates when two controllers
	// deliver the same command (one fleet, several houses).
	if msg.Type == protocol.TypeCommand && msg.CmdID == "" {
		msg.CmdID = fmt.Sprintf("c%d-%d", s.idCounter.Add(1), time.Now().UnixNano())
	}
	if strings.HasPrefix(ac.id, "agent-ntfy-") {
		name := ac.ntfyName()
		s.trackCmd(msg, ac.id) // relay loss is real: retry if no output
		if payload, enc := s.e2eSealMsg(name, msg); enc {
			return relay.PublishEnvelope(relay.Envelope{From: "controller", To: name, Payload: payload, Enc: true, Time: time.Now().UnixMilli()})
		}
		return relay.PublishTo("controller", name, msg)
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
		if payload, enc := s.e2eSealMsg(host, msg); enc {
			env = relay.Envelope{From: "controller", To: host, Payload: payload, Enc: true, Time: time.Now().UnixMilli()}
		} else {
			env = relay.Envelope{From: "controller", To: host, Payload: mustJSON(msg), Time: time.Now().UnixMilli()}
		}
		// Publish on both buses: the agent sits on one, so exactly one
		// copy ever arrives — but a primary-only publish vanishes when the
		// agent picked the other broker. Secondary goes async: publish
		// blocks up to 10s on a blackholed bus, and serial would double
		// worst-case command latency.
		s.trackCmd(msg, ac.id) // relay loss is real: retry if no output
		if bus2 != nil {
			go bus2.PublishCmd(host, env)
		}
		if bus != nil {
			return bus.PublishCmd(host, env)
		}
		return nil
	}
	if err := ac.send(msg); err != nil {
		// Direct link died: fail over to the same host's relay record
		// (mqtt preferred, ntfy last) instead of dropping the command.
		// CmdID dedupe on the agent makes double delivery harmless.
		if sib := s.siblingRelay(ac); sib != nil {
			log.Printf("[failover] %s direct failed (%v), retrying via %s", ac.hostname, err, sib.id)
			return s.sendToAgent(sib, msg)
		}
		return err
	}
	return nil
}

// siblingRelay finds another record for the same hostname on a relay
// transport (mqtt preferred over ntfy), excluding the given record.
func (s *Server) siblingRelay(ac *AgentConn) *AgentConn {
	if ac == nil || ac.hostname == "" {
		return nil
	}
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	var ntfy *AgentConn
	for _, v := range s.agents {
		if v == ac || v.hostname != ac.hostname {
			continue
		}
		if strings.HasPrefix(v.id, "agent-mqtt-") {
			return v
		}
		if strings.HasPrefix(v.id, "agent-ntfy-") && ntfy == nil {
			ntfy = v
		}
	}
	return ntfy
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
	ac := &AgentConn{conn: conn, enc: enc, hostname: first.Hostname, user: first.User, id: id, version: first.Version, untrusted: untrusted}
	s.setAgent(ac)
	if first.Version != "" && first.Version != version.Version {
		log.Printf("[update] %s is outdated (%s vs %s) — push update available", first.Hostname, first.Version, version.Version)
	}
	s.noteHello(id, first.Hostname, first.Version, first.RollbackBad, first.RollbackTo, first.Prot, first.ProtDetail)
	fmt.Printf("\n[+] Agent connected: id=%s hostname=%s user=%s version=%s remote=%s\n", id, first.Hostname, first.User, first.Version, conn.RemoteAddr())
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
			s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq})
		case protocol.TypeTile:
			// Changed tiles are never written to disk (keyframes still save
			// via TypeScreen); they stream straight to the UI compositor.
			s.broadcastWS(map[string]interface{}{"type": "tile", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq})
		case protocol.TypeFileDlChunk:
			s.handleFileDlChunk(id, msg)
		case protocol.TypeMouse:
			s.broadcastWS(map[string]interface{}{"type": "mouse", "id": id, "x": msg.X, "y": msg.Y, "buttons": msg.Buttons})
		case protocol.TypeOutput:
			s.ackCmd(msg.CmdID)
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

func (s *Server) handleScreen(msg protocol.Message, id string) {
	if msg.Data == "" {
		return
	}
	if len(msg.Data) > maxScreenBytes*4/3+1024 {
		fmt.Printf("\n[screen:%s] payload too large (%d chars), dropped\n> ", id, len(msg.Data))
		return
	}
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
	// EVERY frame is pure hot-path waste during a live stream. A missed
	// rotate here only delays cleanup; the next one catches up.
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

// ntfyLoop long-polls for agent messages over HTTPS (no port forward needed).
// relay.Poll blocks up to ~60s when idle: one hanging GET, not a hot loop.
func (s *Server) ntfyLoop() {
	for {
		select {
		case <-s.closeCh:
			return
		default:
		}
		envs, err := relay.Poll("controller", "")
		if err != nil {
			log.Printf("[ntfy] poll: %v", err)
			select {
			case <-s.closeCh:
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		for _, env := range envs {
			if !strings.HasPrefix(env.From, "agent:") {
				continue
			}
			name := strings.TrimPrefix(env.From, "agent:")
			payload := env.Payload
			if env.Enc {
				plain, ok := s.e2eDecryptEnv(name, env)
				if !ok {
					continue
				}
				payload = plain
			}
			var msg protocol.Message
			if err := json.Unmarshal(payload, &msg); err != nil {
				continue
			}
			// Key exchange precedes registration (no agent entry needed).
			if msg.Type == protocol.TypeKeyExchange {
				s.e2eKeyxchg(name, msg.Data)
				continue
			}
			hostname := msg.Hostname
			if hostname == "" {
				hostname = name
			}
			inst := msg.Instance
			if inst == "" {
				inst = name // old agents without instance ids
			}
		id := "agent-ntfy-" + inst
		allow, untrusted := s.checkAuth(msg, id)
		if !allow {
			continue
		}
		s.agentsMu.RLock()
		ac, exists := s.agents[id]
		s.agentsMu.RUnlock()
		// Stash version from hello ("" = old agent).
			if msg.Version != "" {
				s.agentsMu.Lock()
				if ex, ok := s.agents[id]; ok {
					ex.version = msg.Version
				}
				s.agentsMu.Unlock()
			}
		if !exists && msg.Type == protocol.TypeConnect {
			ac = &AgentConn{hostname: hostname, user: msg.User, id: id, version: msg.Version, untrusted: untrusted}
			s.setAgent(ac)
			fmt.Printf("\n[+] Ntfy agent connected: %s (%s) v%s\n", hostname, id, msg.Version)
			_ = relay.PublishTo("controller", name, protocol.Message{Type: protocol.TypeConnected, ID: id, E2E: true, RollbackAck: msg.RollbackBad != ""})
			s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("Ntfy agent %s connected", hostname), "success": true})
			s.noteHello(id, hostname, msg.Version, msg.RollbackBad, msg.RollbackTo, msg.Prot, msg.ProtDetail)
			continue
		}
		if !exists {
			continue
		}
		ac.touch()
		switch msg.Type {
		case protocol.TypeConnect:
			if msg.Version != "" {
				ac.version = msg.Version
			}
			ac.untrusted = untrusted
			s.noteHello(id, hostname, msg.Version, msg.RollbackBad, msg.RollbackTo, msg.Prot, msg.ProtDetail)
			_ = relay.PublishTo("controller", name, protocol.Message{Type: protocol.TypeConnected, ID: id, E2E: true, RollbackAck: msg.RollbackBad != ""})
			case protocol.TypeOutput:
					s.ackCmd(msg.CmdID)
					s.noteUpdateHave(id, msg.Result)
					s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": msg.Result, "error": msg.Error, "success": msg.Error == ""})
					if msg.Error == "" {
						s.broadcastAudiolistIfJSON(msg.Result, id)
					}
					fmt.Printf("\n[ntfy output:%s]\n%s\n> ", name, msg.Result)
  	case protocol.TypeScreen:
  		s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq})
  		s.handleScreen(msg, id)
			case protocol.TypeTile:
					s.broadcastWS(map[string]interface{}{"type": "tile", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq})
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

// sweepLoop evicts relay agents (ntfy/mqtt) unseen for ntfyStaleAfter.
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
func (s *Server) mqttLoop() {
	watch := time.NewTicker(20 * time.Second)
	defer watch.Stop()
	for {
		select {
		case <-s.closeCh:
			return
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
			if err := nb.Subscribe(func(topic string, env relay.Envelope) {
				s.mqttLastMsg1.Store(time.Now().UnixNano())
				s.handleMQTTMsg(topic, env)
			}); err != nil {
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
				if err := nb2.Subscribe(func(topic string, env relay.Envelope) {
					s.mqttLastMsg2.Store(time.Now().UnixNano())
					s.handleMQTTMsg(topic, env)
				}); err != nil {
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
	payload := env.Payload
	if env.Enc {
		plain, ok := s.e2eDecryptEnv(hostHint, env)
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
	if msg.Type == protocol.TypeKeyExchange {
		s.e2eKeyxchg(hostHint, msg.Data)
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
			ac := &AgentConn{hostname: host, user: msg.User, id: id, version: msg.Version, untrusted: untrusted}
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
			ac.untrusted = untrusted
		}
		s.noteHello(id, host, msg.Version, msg.RollbackBad, msg.RollbackTo, msg.Prot, msg.ProtDetail)
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
  		s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "ox": msg.OX, "oy": msg.OY, "format": msg.Format, "fseq": msg.FSeq})
  		s.handleScreen(msg, id)
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


