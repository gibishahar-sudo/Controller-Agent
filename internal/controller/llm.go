package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Local LLM sidecar for Jarvis reply phrasing (P0 verdict: intent parsing
// stays rules-based; phrasing proved 6/6 grounded). llama.cpp llama-server
// over localhost HTTP — no cgo (vet -unsafeptr=false forbids it), no new Go
// dependencies. Windows-only v1 (the prebuilt asset is win-x64); controller
// PC only — never the tablet (battery/RAM), never agents (stealth).
//
// Supply chain: binary + model download once (background, announced),
// both sha256-pinned below and verified after fetch + once per boot.
// Unsigned third-party exe: runs on the operator's own controller PC only.

const (
	llmServerTag = "b11445"
	llmServerURL = "https://github.com/ggml-org/llama.cpp/releases/download/b11445/llama-b11445-bin-win-cpu-x64.zip"
	llmServerSHA = "6918f1695ec80ab09b88e743fc03df5d1f53b8ba755735f9c542204c4b143776"
	llmModelURL  = "https://huggingface.co/bartowski/Llama-3.2-1B-Instruct-GGUF/resolve/main/Llama-3.2-1B-Instruct-Q4_K_M.gguf?download=true"
	llmModelSHA  = "6f85a640a97cf2bf5b8e764087b1e83da0fdb51d7c9fab7d0fece9385611df83"
	llmModelSize = 807694464
	llmPort      = "17877"
	llmIdleKill  = 5 * time.Minute
	llmWarmIdle  = 30 * time.Minute
	llmTimeout   = 6 * time.Second
	llmCacheCap  = 200
)

type llmState struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	verified  bool // shas checked this boot
	ready     bool // files present + verified
	pulling   bool
	pullPct   int
	pullWhat  string
	lastUse   time.Time
	lastErr   string
	idleT     *time.Timer
	stopPull  bool
	starting  bool
	startDone chan struct{}
	// Phrase cache: (text + callMe) -> phrased line. Repeat replies
	// (help, greetings, recall openers) skip the model entirely.
	phraseCache map[string]string
	phraseOrder []string // FIFO eviction order, capped at llmCacheCap
	lastOK      time.Time // last successful completion: skips the /health probe while fresh
	warm        bool      // warm standby: prewarmed at boot, long idle window
}

func newLLMState() *llmState { return &llmState{phraseCache: map[string]string{}} }

// phraseKey scopes cache entries by addressee (callMe changes the line).
func phraseKey(text, callMe string) string { return text + "\x00" + callMe }

// phraseGet/phrasePut are the bounded FIFO cache (caller need not hold mu).
func (st *llmState) phraseGet(key string) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	line, ok := st.phraseCache[key]
	return line, ok
}

func (st *llmState) phrasePut(key, line string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.phraseCache == nil {
		st.phraseCache = map[string]string{}
	}
	if _, dup := st.phraseCache[key]; !dup {
		st.phraseOrder = append(st.phraseOrder, key)
	}
	st.phraseCache[key] = line
	for len(st.phraseOrder) > llmCacheCap {
		old := st.phraseOrder[0]
		st.phraseOrder = st.phraseOrder[1:]
		delete(st.phraseCache, old)
	}
}

// idleKillDur is short by default (RAM back fast), long on warm standby.
func (st *llmState) idleKillDur() time.Duration {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.warm {
		return llmWarmIdle
	}
	return llmIdleKill
}

// llmHome mirrors memoryFile: beside the exe (installed) or CWD (dev).
func llmHome() string {
	base := ""
	if exe, err := os.Executable(); err == nil {
		base = filepath.Dir(exe)
	}
	if base == "" {
		if cwd, err := os.Getwd(); err == nil {
			base = cwd
		} else {
			base = "."
		}
	}
	dir := filepath.Join(base, "llm")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

func llmBinDir() string { return filepath.Join(llmHome(), "bin") }
func llmExe() string    { return filepath.Join(llmBinDir(), "llama-server.exe") }
func llmModel() string  { return filepath.Join(llmHome(), "model.gguf") }

func shaFileHex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// llmStatus reports one line for llm-status and logs.
func (s *Server) llmStatus() string {
	st := s.llm
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pulling {
		return fmt.Sprintf("pulling %s %d%%", st.pullWhat, st.pullPct)
	}
	if st.cmd != nil && st.cmd.Process != nil {
		idle := time.Since(st.lastUse).Round(time.Second)
		return fmt.Sprintf("ready (pid %d, idle %s)%s, cache %d", st.cmd.Process.Pid, idle, warmTag(st), len(st.phraseCache))
	}
	// Files may have arrived without us (bundled installer): detect once.
	if !st.verified {
		if err := llmVerifyFiles(); err == nil {
			st.verified = true
			st.ready = true
		}
	}
	if st.ready {
		return fmt.Sprintf("ready (server down, starts on demand)%s, cache %d", warmTag(st), len(st.phraseCache))
	}
	if st.lastErr != "" {
		return "down: " + st.lastErr
	}
	return "down (no model — first llm-say pulls ~800MB in background)"
}

// warmTag reports the standby flag for the status line (caller holds mu).
func warmTag(st *llmState) string {
	if st.warm {
		return " warm-standby"
	}
	return ""
}

// llmEnsure verifies files (once per boot) and starts the server.
// Returns errLLMNeedPull when a fetch is required.
var errLLMNeedPull = fmt.Errorf("model not present")

func (s *Server) llmEnsure() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("sidecar is windows-only")
	}
	st := s.llm
	st.mu.Lock()
	if !st.verified {
		if err := llmVerifyFiles(); err != nil {
			st.lastErr = err.Error()
			st.mu.Unlock()
			return err
		}
		st.verified = true
		st.ready = true
	}
	if st.cmd != nil && st.cmd.Process != nil && llmHealthy() {
		st.lastUse = time.Now()
		st.armIdleLocked()
		st.mu.Unlock()
		return nil
	}
	st.cmd = nil
	if st.starting {
		ch := st.startDone
		st.mu.Unlock()
		select {
		case <-ch:
		case <-time.After(30 * time.Second):
		}
		return s.llmEnsureRecheck()
	}
	st.starting = true
	st.startDone = make(chan struct{})
	st.mu.Unlock()
	err := s.llmStartAndWait()
	st.mu.Lock()
	st.starting = false
	close(st.startDone)
	if err != nil {
		st.lastErr = err.Error()
		st.mu.Unlock()
		return err
	}
	st.lastErr = ""
	st.lastUse = time.Now()
	st.armIdleLocked()
	st.mu.Unlock()
	return nil
}

// llmEnsureRecheck re-examines state after waiting on a concurrent start.
func (s *Server) llmEnsureRecheck() error {
	st := s.llm
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.cmd != nil && st.cmd.Process != nil && llmHealthy() {
		st.lastUse = time.Now()
		st.armIdleLocked()
		return nil
	}
	if st.lastErr != "" {
		return fmt.Errorf("%s", st.lastErr)
	}
	return fmt.Errorf("sidecar starting, retry")
}

func llmVerifyFiles() error {
	for _, want := range []struct {
		path, sha string
		size      int64 // 0 = skip size check
	}{
		{llmExe(), "", 0}, // exe verified inside the zip at pull time
		{llmModel(), llmModelSHA, llmModelSize},
	} {
		st, err := os.Stat(want.path)
		if err != nil {
			return errLLMNeedPull
		}
		if want.size > 0 && st.Size() != want.size {
			return fmt.Errorf("size drift %s", want.path)
		}
		if want.sha != "" {
			sum, err := shaFileHex(want.path)
			if err != nil || sum != want.sha {
				return fmt.Errorf("hash drift %s", want.path)
			}
		}
	}
	return nil
}

func llmHealthy() bool {
	c := &http.Client{Timeout: 3 * time.Second}
	r, err := c.Get("http://127.0.0.1:" + llmPort + "/health")
	if err != nil {
		return false
	}
	defer r.Body.Close()
	return r.StatusCode == 200
}

// llmStartAndWait launches the sidecar without holding st.mu (health
// polling takes up to ~25s on first boot while the model loads).
func (s *Server) llmStartAndWait() error {
	st := s.llm
	args := []string{"-m", llmModel(), "--port", llmPort, "-c", "512", "-t", llmThreads(), "--log-disable"}
	cmd := exec.Command(llmExe(), args...)
	cmd.Dir = llmBinDir() // dll search: exe dir first
	if err := cmd.Start(); err != nil {
		return err
	}
	st.mu.Lock()
	st.cmd = cmd
	st.mu.Unlock()
	go func() {
		_ = cmd.Wait()
		st.mu.Lock()
		if st.cmd == cmd {
			st.cmd = nil
		}
		st.mu.Unlock()
	}()
	for i := 0; i < 50; i++ {
		if llmHealthy() {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	st.mu.Lock()
	if st.cmd == cmd {
		st.cmd = nil
	}
	st.mu.Unlock()
	return fmt.Errorf("server would not get healthy")
}

func llmThreads() string {
	n := runtime.NumCPU() - 2
	if n < 2 {
		n = 2
	}
	return fmt.Sprintf("%d", n)
}

// armIdleLocked (re)arms the idle killer (caller holds st.mu). Warm
// standby keeps the server half an hour; default gives RAM back in five.
func (st *llmState) armIdleLocked() {
	if st.idleT != nil {
		st.idleT.Stop()
	}
	dur := llmIdleKill
	if st.warm {
		dur = llmWarmIdle
	}
	st.idleT = time.AfterFunc(dur, func() {
		// Kill only if still idle (a fresh use re-arms).
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.cmd == nil || st.cmd.Process == nil {
			return
		}
		idle := llmIdleKill
		if st.warm {
			idle = llmWarmIdle
		}
		if time.Since(st.lastUse) < idle {
			return
		}
		_ = st.cmd.Process.Kill()
		st.cmd = nil
	})
}

// llmPull fetches binary+model in the background (announced, cancellable
// via llm-stop). Concurrent pulls coalesce.
func (s *Server) llmPull() string {
	if runtime.GOOS != "windows" {
		return "sidecar is windows-only"
	}
	st := s.llm
	st.mu.Lock()
	// Bundled installer already placed verified files: nothing to fetch.
	if !st.verified {
		if err := llmVerifyFiles(); err == nil {
			st.verified = true
			st.ready = true
		}
	}
	if st.ready {
		ready := fmt.Sprintf("model already present (~800MB on disk)%s — say llm-warm on to prewarm", warmTag(st))
		st.mu.Unlock()
		return ready
	}
	if st.pulling {
		p := fmt.Sprintf("already pulling %s %d%%", st.pullWhat, st.pullPct)
		st.mu.Unlock()
		return p
	}
	st.pulling = true
	st.stopPull = false
	st.pullPct = 0
	st.mu.Unlock()
	go s.llmPullRun()
	return "pulling model+server in background (~820MB first time) — llm-status tracks it"
}

func (s *Server) llmPullRun() {
	st := s.llm
	defer func() {
		st.mu.Lock()
		st.pulling = false
		st.mu.Unlock()
	}()
	setPhase := func(what string) {
		st.mu.Lock()
		st.pullWhat = what
		st.pullPct = 0
		st.mu.Unlock()
	}
	// 1. Server zip (small): download, verify, unpack to bin/.
	setPhase("server")
	zpath := filepath.Join(llmHome(), "llama.zip.tmp")
	if err := llmFetch(llmServerURL, zpath, 0, st, "server"); err != nil {
		st.mu.Lock()
		st.lastErr = err.Error()
		st.mu.Unlock()
		log.Printf("[llm] pull server: %v", err)
		return
	}
	sum, err := shaFileHex(zpath)
	if err != nil || sum != llmServerSHA {
		os.Remove(zpath)
		st.mu.Lock()
		st.lastErr = "server hash mismatch"
		st.mu.Unlock()
		log.Printf("[llm] pull server: hash mismatch")
		return
	}
	if err := llmUnzipBin(zpath, llmBinDir()); err != nil {
		st.mu.Lock()
		st.lastErr = err.Error()
		st.mu.Unlock()
		log.Printf("[llm] unpack server: %v", err)
		return
	}
	os.Remove(zpath)
	// 2. Model (big): download, size+hash verify.
	setPhase("model")
	mpath := filepath.Join(llmHome(), "model.gguf.tmp")
	if err := llmFetch(llmModelURL, mpath, llmModelSize, st, "model"); err != nil {
		st.mu.Lock()
		st.lastErr = err.Error()
		st.mu.Unlock()
		log.Printf("[llm] pull model: %v", err)
		return
	}
	sum, err = shaFileHex(mpath)
	if err != nil || sum != llmModelSHA {
		os.Remove(mpath)
		st.mu.Lock()
		st.lastErr = "model hash mismatch"
		st.mu.Unlock()
		log.Printf("[llm] pull model: hash mismatch")
		return
	}
	os.Rename(mpath, llmModel())
	st.mu.Lock()
	st.ready = true
	st.verified = true
	st.lastErr = ""
	st.mu.Unlock()
	log.Printf("[llm] pull complete — sidecar ready")
	s.broadcastWS(map[string]interface{}{"type": "output", "data": "🗣 local model ready.", "success": true})
}

// llmFetch streams url to dst with progress + stopPull checks. wantSize>0
// pre-sizes expectations (0 = unknown).
func llmFetch(url, dst string, wantSize int64, st *llmState, what string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 0} // bounded by stopPull + read activity, not wall clock
	r, err := c.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("fetch %s: http %d", what, r.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	total := r.ContentLength
	if total <= 0 {
		total = wantSize
	}
	var got int64
	lastPct := -1
	chunk := make([]byte, 1<<20)
	for {
		st.mu.Lock()
		stop := st.stopPull
		st.mu.Unlock()
		if stop {
			return fmt.Errorf("pull cancelled")
		}
		n, err := r.Body.Read(chunk)
		if n > 0 {
			got += int64(n)
			if _, werr := out.Write(chunk[:n]); werr != nil {
				return werr
			}
			if total > 0 {
				pct := int(100 * got / total)
				if pct != lastPct && pct%5 == 0 {
					lastPct = pct
					st.mu.Lock()
					st.pullPct = pct
					st.mu.Unlock()
				}
			}
		}
		if err != nil {
			break
		}
	}
	if total > 0 && got != total {
		return fmt.Errorf("fetch %s: short (%d/%d)", what, got, total)
	}
	return nil
}

// llmUnzipBin extracts only llama-server.exe + required dlls (the zip
// carries benchmarks and tools we never run on the controller).
func llmUnzipBin(zpath, dst string) error {
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	// PowerShell-free unzip via .NET would need exec; instead shell to the
	// platform expander (present on every supported controller box).
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Expand-Archive -Path %q -DestinationPath %q -Force`, zpath, dst+"-x"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("expand: %v %.200s", err, out)
	}
	xdir := dst + "-x"
	defer os.RemoveAll(xdir)
	keep := func(name string) bool {
		l := strings.ToLower(name)
		if strings.HasSuffix(l, "llama-server.exe") {
			return true
		}
		return strings.HasSuffix(l, ".dll")
	}
	moved := 0
	err := filepath.Walk(xdir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !keep(info.Name()) {
			return err
		}
		dst := filepath.Join(dst, info.Name())
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := io.Copy(out, in); err != nil {
			return err
		}
		moved++
		return nil
	})
	if err != nil {
		return err
	}
	if moved == 0 {
		return fmt.Errorf("no server binary in zip")
	}
	return nil
}

// llmStop kills the server and cancels any pull.
func (s *Server) llmStop() string {
	st := s.llm
	st.mu.Lock()
	defer st.mu.Unlock()
	st.stopPull = true
	if st.idleT != nil {
		st.idleT.Stop()
	}
	if st.cmd != nil && st.cmd.Process != nil {
		_ = st.cmd.Process.Kill()
		st.cmd = nil
		return "sidecar stopped"
	}
	return "sidecar already down"
}

// tryLLMCmd routes controller-side llm pseudo-commands (llm-say, llm-pull,
// llm-stop, llm-status, llm-warm). Everything answers directly via
// broadcast; nothing reaches agents. Returns handled + reply (reply is for
// callers with a local screen; WS/HTTP already got the broadcast).
func (s *Server) tryLLMCmd(cmd string) (bool, string) {
	t := strings.TrimSpace(cmd)
	lt := strings.ToLower(t)
	answer := func(text string) (bool, string) {
		rep := "🗣 " + text
		s.broadcastWS(map[string]interface{}{"type": "output", "data": rep, "success": true})
		return true, rep
	}
	switch {
	case lt == "llm-status":
		return answer(s.llmStatus())
	case lt == "llm-stop":
		return answer(s.llmStop())
	case lt == "llm-pull":
		return answer(s.llmPull())
	case lt == "llm-warm" || lt == "llm-warm on" || lt == "llm-warm off":
		return answer(s.llmWarm(lt))
	case lt == "llm-say" || strings.HasPrefix(lt, "llm-say "):
		text := strings.TrimSpace(t[len("llm-say"):])
		if text == "" {
			return answer("say what? llm-say <text>")
		}
		if line, err := s.llmSay(text); err != nil {
			return answer(line + " (" + err.Error() + ")")
		} else {
			return answer(line)
		}
	}
	return false, ""
}

// llmWarm toggles warm standby (pref persisted in memory.json): on keeps
// the sidecar up for 30 idle minutes and prewarms it now; off returns to
// the 5-minute idle killer. "llm-warm" alone reports the flag. Prewarm
// starts only when files verify — never a surprise 800MB pull.
func (s *Server) llmWarm(lt string) string {
	on := strings.HasSuffix(lt, " on")
	off := strings.HasSuffix(lt, " off")
	s.memoryMu.Lock()
	if on {
		s.memory.Prefs["llmWarm"] = "1"
	} else if off {
		delete(s.memory.Prefs, "llmWarm")
	}
	warmed := s.memory.Prefs["llmWarm"] == "1"
	saveMemoryFile(s.memory)
	s.memoryMu.Unlock()
	st := s.llm
	st.mu.Lock()
	st.warm = warmed
	st.mu.Unlock()
	if off {
		s.llmStop()
		return "standby off (5-minute idle killer)"
	}
	if on {
		if err := llmVerifyFiles(); err != nil {
			return "standby on — files not present, llm-pull first"
		}
		go func() {
			if err := s.llmEnsure(); err != nil {
				log.Printf("[llm] prewarm: %v", err)
			}
		}()
		return "standby on (30-minute idle window, prewarming now)"
	}
	if warmed {
		return "standby on (30-minute idle window)"
	}
	return "standby off (5-minute idle killer)"
}

// llmPhraseIfReady phrases text through the model ONLY when the sidecar
// is already warm (running + healthy). Never starts a pull, never blocks
// hunting one: cold return ("", false) keeps the raw text on its way.
// Also returns false for very short text (< 40 chars) — phrasing a
// 5-word reply adds latency for no benefit. Repeat texts hit the phrase
// cache (no model call at all); a recent success skips the /health probe.
func (s *Server) llmPhraseIfReady(text string) (string, bool) {
	if s.llm == nil {
		return "", false
	}
	text = strings.TrimSpace(text)
	if len(text) < 40 {
		return "", false
	}
	callMe := ""
	s.memoryMu.Lock()
	if cm, ok := s.memory.Prefs["callMe"]; ok {
		callMe = strings.TrimSpace(cm)
	}
	s.memoryMu.Unlock()
	st := s.llm
	if line, ok := st.phraseGet(phraseKey(text, callMe)); ok {
		return line, true
	}
	st.mu.Lock()
	running := st.cmd != nil && st.cmd.Process != nil
	fresh := time.Since(st.lastOK) < time.Minute
	st.mu.Unlock()
	if !running || (!fresh && !llmHealthy()) {
		return "", false
	}
	line, err := s.llmSay(text)
	if err != nil || line == "" || len(line) > 200 {
		return "", false
	}
	return line, true
}

// llmSay phrases operator-result text into one short Jarvis line (proven
// P0r job: grounded, no invention). Auto-pulls on first need (voted);
// while pulling, answers with the unphrased text once. Repeat texts hit
// the cache; 32 output tokens + 6s timeout keep slow boxes from stalling
// the voice path (failures keep the raw text).
func (s *Server) llmSay(ctxText string) (string, error) {
	ctxText = strings.TrimSpace(ctxText)
	if ctxText == "" {
		return "", fmt.Errorf("nothing to phrase")
	}
	if s.llm == nil {
		return ctxText, fmt.Errorf("sidecar unavailable")
	}
	callMe := ""
	s.memoryMu.Lock()
	if cm, ok := s.memory.Prefs["callMe"]; ok {
		callMe = strings.TrimSpace(cm)
	}
	s.memoryMu.Unlock()
	if line, ok := s.llm.phraseGet(phraseKey(ctxText, callMe)); ok {
		return line, nil
	}
	if err := s.llmEnsure(); err != nil {
		if err == errLLMNeedPull {
			go s.llmPull()
			return ctxText, fmt.Errorf("pulling model in background (~800MB once)")
		}
		return ctxText, err
	}
	sys, user := llmPrompt(ctxText, callMe)
	line, err := s.llmComplete(sys, user, 0.2, 32, llmTimeout)
	if err != nil {
		return ctxText, err
	}
	if line = llmCleanLine(line); line == "" || len(line) > 200 {
		return ctxText, fmt.Errorf("bad model reply")
	}
	s.llm.phrasePut(phraseKey(ctxText, callMe), line)
	return line, nil
}

// llmPrompt builds the proven P0r phrasing prompt (short, grounded).
// The word cap keeps generations short: faster replies, shorter TTS.
func llmPrompt(ctxText, callMe string) (sys, user string) {
	sys = "Reply with ONE short line only, no quotes, no JSON. Keep it under 20 words."
	user = ctxText + ". Say it in one short Jarvis-style line."
	if callMe != "" {
		user += " Address the operator as " + callMe + "."
	}
	return sys, user
}

// llmCleanLine trims model wrapper quotes/space; empty stays empty.
func llmCleanLine(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

// llmComplete posts one chat completion (temp/maxTokens bounded) and
// returns the raw content. Serialized: one in-flight model call. Success
// stamps lastOK so the next phrasing skips the /health probe.
func (s *Server) llmComplete(sys, user string, temp float64, maxTokens int, timeout time.Duration) (string, error) {
	st := s.llm
	st.mu.Lock()
	st.lastUse = time.Now()
	st.armIdleLocked()
	st.mu.Unlock()
	line, err := llmPost("http://127.0.0.1:"+llmPort+"/v1/chat/completions", sys, user, temp, maxTokens, timeout)
	if err == nil {
		st.mu.Lock()
		st.lastOK = time.Now()
		st.mu.Unlock()
	}
	return line, err
}

// llmPost is the transport half of llmComplete (hermetic under tests).
func llmPost(url, sys, user string, temp float64, maxTokens int, timeout time.Duration) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":       "jarvis",
		"messages":    []map[string]string{{"role": "system", "content": sys}, {"role": "user", "content": user}},
		"temperature": temp,
		"max_tokens":  maxTokens,
	})
	c := &http.Client{Timeout: timeout}
	r, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("model http %d", r.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("model returned no choices")
	}
	return out.Choices[0].Message.Content, nil
}
