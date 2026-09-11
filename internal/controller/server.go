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
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"rmm/internal/mqttrelay"
	"rmm/internal/protocol"
	"rmm/internal/relay"
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
	mu       sync.Mutex

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

// mqttHost returns the MQTT topic host for directed commands.
func (a *AgentConn) mqttHost() string {
	if strings.HasPrefix(a.id, "agent-mqtt-") {
		return strings.TrimPrefix(a.id, "agent-mqtt-")
	}
	if a.hostname != "" {
		return a.hostname
	}
	return a.id
}

// ntfyName returns the agent hostname used for directed ntfy delivery.
func (a *AgentConn) ntfyName() string {
	if strings.HasPrefix(a.id, "agent-ntfy-") {
		return strings.TrimPrefix(a.id, "agent-ntfy-")
	}
	if a.hostname != "" {
		return a.hostname
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

	agents        map[string]*AgentConn
	agentsMu      sync.RWMutex
	currentAgent  *AgentConn
	latency       map[string]int64
	latencyMu     sync.RWMutex
	wsClients     map[*wsClient]bool
	wsMu          sync.Mutex
	screenshotDir string
	httpAddr      string

	mqttMu      sync.Mutex
	mqttBus     *mqttrelay.CtrlBus
	mqttLastMsg atomic.Int64 // unixnano of last inbound MQTT message
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
		if opts.AutoOpen {
			go func() {
				time.Sleep(500 * time.Millisecond)
				openBrowser("http://" + opts.HTTPAddr + "/")
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
	return s, nil
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

// Agents returns a snapshot for UI/API.
func (s *Server) Agents() []map[string]interface{} {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	out := make([]map[string]interface{}, 0, len(s.agents))
	for _, a := range s.agents {
		s.latencyMu.RLock()
		lat := s.latency[a.id]
		s.latencyMu.RUnlock()
		out = append(out, map[string]interface{}{
			"id": a.id, "hostname": a.hostname, "user": a.user,
			"connected": true, "latency": lat, "remote": a.remote(),
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
	if strings.HasPrefix(ac.id, "agent-ntfy-") {
		return relay.PublishTo("controller", ac.ntfyName(), msg)
	}
	if strings.HasPrefix(ac.id, "agent-mqtt-") {
		s.mqttMu.Lock()
		bus := s.mqttBus
		s.mqttMu.Unlock()
		if bus == nil {
			return fmt.Errorf("mqtt bus not connected")
		}
		return bus.PublishCmd(ac.mqttHost(), relay.Envelope{From: "controller", To: ac.mqttHost(), Payload: mustJSON(msg), Time: time.Now().UnixMilli()})
	}
	return ac.send(msg)
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
	ac := &AgentConn{conn: conn, enc: enc, hostname: first.Hostname, user: first.User, id: id}
	s.setAgent(ac)
	fmt.Printf("\n[+] Agent connected: id=%s hostname=%s user=%s remote=%s\n", id, first.Hostname, first.User, conn.RemoteAddr())
	_ = ac.send(protocol.Message{Type: protocol.TypeConnected, ID: id})
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
			s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "format": msg.Format})
		case protocol.TypeMouse:
			s.broadcastWS(map[string]interface{}{"type": "mouse", "id": id, "x": msg.X, "y": msg.Y, "buttons": msg.Buttons})
		case protocol.TypeOutput:
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
	s.rotateScreens()
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
			var msg protocol.Message
			if err := json.Unmarshal(env.Payload, &msg); err != nil {
				continue
			}
			if !strings.HasPrefix(env.From, "agent:") {
				continue
			}
			name := strings.TrimPrefix(env.From, "agent:")
			hostname := msg.Hostname
			if hostname == "" {
				hostname = name
			}
			inst := msg.Instance
			if inst == "" {
				inst = name // old agents without instance ids
			}
			id := "agent-ntfy-" + inst
			s.agentsMu.RLock()
			ac, exists := s.agents[id]
			s.agentsMu.RUnlock()
			if !exists && msg.Type == protocol.TypeConnect {
				ac = &AgentConn{hostname: hostname, user: msg.User, id: id}
				s.setAgent(ac)
				fmt.Printf("\n[+] Ntfy agent connected: %s (%s)\n", hostname, id)
				_ = relay.PublishTo("controller", name, protocol.Message{Type: protocol.TypeConnected, ID: id})
				s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("Ntfy agent %s connected", hostname), "success": true})
				continue
			}
			if !exists {
				continue
			}
			ac.touch()
			switch msg.Type {
			case protocol.TypeConnect:
				_ = relay.PublishTo("controller", name, protocol.Message{Type: protocol.TypeConnected, ID: id})
			case protocol.TypeOutput:
					s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": msg.Result, "error": msg.Error, "success": msg.Error == ""})
					if msg.Error == "" {
						s.broadcastAudiolistIfJSON(msg.Result, id)
					}
					fmt.Printf("\n[ntfy output:%s]\n%s\n> ", name, msg.Result)
				case protocol.TypeScreen:
						s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "format": msg.Format})
						s.handleScreen(msg, id)
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
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
		}
		now := time.Now()
		var stale []string
		s.agentsMu.RLock()
		for id, a := range s.agents {
			if !strings.HasPrefix(id, "agent-ntfy-") && !strings.HasPrefix(id, "agent-mqtt-") {
				continue
			}
			if now.Sub(a.seen()) > ntfyStaleAfter {
				stale = append(stale, id)
			}
		}
		s.agentsMu.RUnlock()
		for _, id := range stale {
			fmt.Printf("\n[-] Relay agent %s stale, evicting\n> ", id)
			s.removeAgent(id)
		}
	}
}

// mqttLoop keeps one MQTT bus connected (rotating brokers on failure) and
// routes inbound agent messages. paho auto-reconnects transient drops; the
// watchdog below re-dials if a connected bus goes silent while MQTT agents
// exist (broker blackhole without TCP close).
func (s *Server) mqttLoop() {
	watch := time.NewTicker(60 * time.Second)
	defer watch.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		default:
		}
		s.mqttMu.Lock()
		bus := s.mqttBus
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
			if err := nb.Subscribe(s.handleMQTTMsg); err != nil {
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
			continue
		}
		// Watchdog: silent bus + live MQTT agents = suspected blackhole.
		select {
		case <-s.closeCh:
			return
		case <-watch.C:
		}
		if time.Since(time.Unix(0, s.mqttLastMsg.Load())) > 3*time.Minute && s.hasMQTTAgents() {
			log.Printf("[mqtt] silent with live agents, re-dialing")
			s.mqttMu.Lock()
			s.mqttBus = nil
			s.mqttMu.Unlock()
			bus.Close()
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
	var msg protocol.Message
	if err := json.Unmarshal(env.Payload, &msg); err != nil {
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
		s.agentsMu.RLock()
		_, exists := s.agents[id]
		s.agentsMu.RUnlock()
		if !exists {
			ac := &AgentConn{hostname: host, user: msg.User, id: id}
			s.setAgent(ac)
			fmt.Printf("\n[+] MQTT agent connected: %s (%s)\n", host, id)
			s.mqttMu.Lock()
			bus := s.mqttBus
			s.mqttMu.Unlock()
			if bus != nil {
				_ = bus.PublishCmd(host, relay.Envelope{From: "controller", To: host, Payload: mustJSON(protocol.Message{Type: protocol.TypeConnected, ID: id}), Time: time.Now().UnixMilli()})
			}
			s.broadcastWS(map[string]interface{}{"type": "output", "data": fmt.Sprintf("MQTT agent %s connected", host), "success": true})
		}
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
	id := "agent-mqtt-" + host
	s.agentsMu.RLock()
	ac, exists := s.agents[id]
	s.agentsMu.RUnlock()
	if !exists {
		return
	}
	ac.touch()
	switch msg.Type {
			case protocol.TypeOutput:
				s.broadcastWS(map[string]interface{}{"type": "output", "id": id, "data": msg.Result, "error": msg.Error, "success": msg.Error == ""})
				if msg.Error == "" {
					s.broadcastAudiolistIfJSON(msg.Result, id)
				}
				if strings.Contains(msg.Result, "\"entries\"") && strings.Contains(msg.Result, "\"path\"") {
					s.broadcastWS(map[string]interface{}{"type": "filelist", "isRemote": true, "data": msg.Result, "id": id})
				}
				fmt.Printf("\n[mqtt output:%s]\n%s\n> ", host, msg.Result)
	case protocol.TypeScreen:
		s.broadcastWS(map[string]interface{}{"type": "screen", "id": id, "data": msg.Data, "width": msg.Width, "height": msg.Height, "format": msg.Format})
		s.handleScreen(msg, id)
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


