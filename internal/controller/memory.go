package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Jarvis memory (P2): operator-curated facts + name bindings + prefs,
// twin of macros.json (0600 file, mutex, load-on-boot, atomic rewrite).
// Tablet + desktop share it automatically (controller-side). voice-cmd and
// the memory pseudo-command both funnel here; the agent never sees it.

type agentMemory struct {
	Name  string   `json:"name,omitempty"`
	Facts []string `json:"facts,omitempty"`
}

type memoryStore struct {
	Agents map[string]*agentMemory `json:"agents"` // hostname -> memory (hostnames survive restarts; instance ids don't)
	Names  map[string]string       `json:"names"`  // lower(name) -> hostname
	Prefs  map[string]string       `json:"prefs"`  // defaultAgent, replyAloud, callMe
}

// memoryFilePath overrides the file location in tests.
var memoryFilePath = ""

// memoryFile lives beside the exe (installed) or CWD (dev), like macros.
func memoryFile() string {
	if memoryFilePath != "" {
		return memoryFilePath
	}
	if exe, err := os.Executable(); err == nil {
		if st, err := os.Stat(filepath.Join(filepath.Dir(exe), "memory.json")); err == nil && !st.IsDir() {
			return filepath.Join(filepath.Dir(exe), "memory.json")
		}
		if dir := filepath.Dir(exe); dir != "" {
			return filepath.Join(dir, "memory.json")
		}
	}
	return "memory.json"
}

func loadMemoryFile() *memoryStore {
	m := &memoryStore{Agents: map[string]*agentMemory{}, Names: map[string]string{}, Prefs: map[string]string{}}
	b, err := os.ReadFile(memoryFile())
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, m)
	if m.Agents == nil {
		m.Agents = map[string]*agentMemory{}
	}
	if m.Names == nil {
		m.Names = map[string]string{}
	}
	if m.Prefs == nil {
		m.Prefs = map[string]string{}
	}
	return m
}

func saveMemoryFile(m *memoryStore) {
	b, _ := json.MarshalIndent(m, "", " ")
	_ = os.WriteFile(memoryFile(), b, 0600)
}

// --- server wiring (fields live on Server next to macros) ---

func (s *Server) memGet(host string) *agentMemory {
	am, ok := s.memory.Agents[host]
	if !ok {
		am = &agentMemory{}
		s.memory.Agents[host] = am
	}
	return am
}

// --- pure store ops (unit-tested; callers hold memoryMu) ---

// memBindName points name at host. Collision with a different live host is
// refused (caller asks once via "<name> means <host>").
func memBindName(m *memoryStore, name, host string, live func(string) bool) (msg string, bound bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || host == "" {
		return "name what, exactly?", false
	}
	if cur, ok := m.Names[name]; ok && cur != host {
		if live(cur) {
			return fmt.Sprintf("%s already means %s — say '%s means %s' to move it", name, cur, name, host), false
		}
	}
	m.Names[name] = host
	if am, ok := m.Agents[host]; ok {
		am.Name = name
	} else {
		m.Agents[host] = &agentMemory{Name: name}
	}
	return fmt.Sprintf("%s is %s. Got it.", name, host), true
}

// memForgetFragment deletes facts containing frag (case-insensitive) for
// host, or across all hosts when host == "". Returns what was deleted.
func memForgetFragment(m *memoryStore, host, frag string) []string {
	frag = strings.ToLower(strings.TrimSpace(frag))
	if frag == "" {
		return nil
	}
	var hosts []string
	if host != "" {
		hosts = []string{host}
	} else {
		for h := range m.Agents {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
	}
	var deleted []string
	for _, h := range hosts {
		am, ok := m.Agents[h]
		if !ok {
			continue
		}
		kept := am.Facts[:0]
		for _, f := range am.Facts {
			if strings.Contains(strings.ToLower(f), frag) {
				deleted = append(deleted, h+": "+f)
			} else {
				kept = append(kept, f)
			}
		}
		am.Facts = kept
	}
	return deleted
}

// memWipeAgent deletes one host's facts + any name pointers to it.
func memWipeAgent(m *memoryStore, host string) int {
	n := 0
	if am, ok := m.Agents[host]; ok {
		n += len(am.Facts)
		delete(m.Agents, host)
	}
	for name, h := range m.Names {
		if h == host {
			delete(m.Names, name)
			n++
		}
	}
	return n
}

// --- voice conversation context (runtime only, never persisted) ---

// voiceResult is one completed voice-driven agent command.
type voiceResult struct {
	text  string
	run   string
	lines []string
	host  string
	at    time.Time
}

type voicePending struct {
	text string
	run  string
	host string
	ts   time.Time
}

// voiceCtx holds Layer-1 follow-up state: last completed run (repeat +
// recall-cache), one pending wipe gate, in-flight voice commands awaiting
// their outputs (completed by CmdID sniffing), and the last SPOKEN reply
// (TTS poll endpoint serves it to tablets that can't hear the WebView).
type voiceCtx struct {
	last      *voiceResult
	recall    *voiceResult
	spoken    *voiceSpoken
	pendingWipe string
	pendingAt time.Time
	awaiting  map[string]*voicePending
}

// voiceSpoken is one direct reply, for the TTS poll endpoint.
type voiceSpoken struct {
	text string
	at   time.Time
}

func newVoiceCtx() *voiceCtx {
	return &voiceCtx{awaiting: map[string]*voicePending{}}
}

const voiceCtxTTL = 10 * time.Minute

func (s *Server) voiceFresh(v *voiceResult) bool {
	return v != nil && time.Since(v.at) < voiceCtxTTL
}

// noteVoiceResult completes a tracked voice command when its agent output
// lands (called beside ackCmd on BOTH transports). Unknown CmdIDs are a
// no-op. Lines capped at 20; errors still record (as failures to report).
// When the box visibly failed the run (unknown verb, transport error),
// Jarvis says so with a next step instead of letting the raw error sit
// unexplained — the notice is a direct reply, never a new run, so it
// cannot recurse.
func (s *Server) noteVoiceResult(cmdID, result, errStr string) {
	if cmdID == "" {
		return
	}
	op := s.opName() // before voiceMu: opName locks memoryMu (no reentry)
	s.voiceMu.Lock()
	p, ok := s.voice.awaiting[cmdID]
	if !ok {
		s.voiceMu.Unlock()
		return
	}
	delete(s.voice.awaiting, cmdID)
	if len(s.voice.awaiting) > 50 {
		// Prune oldest beyond bound (clock skew-proof: map iteration +
		// delete is fine, exact victim irrelevant).
		for k := range s.voice.awaiting {
			delete(s.voice.awaiting, k)
			break
		}
	}
	text := result
	if errStr != "" {
		text = "ERROR: " + errStr
	}
	var lines []string
	for _, ln := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(strings.TrimRight(ln, "\r")); t != "" {
			lines = append(lines, t)
		}
		if len(lines) >= 20 {
			break
		}
	}
	s.voice.last = &voiceResult{text: p.text, run: p.run, lines: lines, host: p.host, at: time.Now()}
	failed := errStr != "" || voiceRunFailed(text)
	run, host := p.run, p.host
	s.voiceMu.Unlock()
	if !failed {
		return
	}
	hint := "try 'voice-cmd help'"
	if min, ok := cmdMinVersion[cmdVerb(run)]; ok {
		hint = "update the box past " + min
	} else if strings.HasPrefix(run, "run-powershell ") {
		hint = "even the fallback didn't land — that box may block PowerShell, update it"
	}
	s.broadcastWS(map[string]interface{}{"type": "output", "id": host,
		"data": fmt.Sprintf("🎙 That didn't land on %s (%s), %s — %s.", host, cmdVerb(run), op, hint), "success": true})
}

// voiceRunFailed spots agent-side rejection in result text (cmd.exe and
// PowerShell both phrase it as not-recognized; the dispatcher says
// unknown command). Pure for tests.
func voiceRunFailed(text string) bool {
	l := strings.ToLower(text)
	return strings.Contains(l, "not recognized") || strings.Contains(l, "unknown command")
}
