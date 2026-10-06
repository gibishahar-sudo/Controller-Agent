package controller

import (
	"strings"
	"testing"
)

// memTestServer builds a Server with memory + voice context only (no
// network, no agents map needed for store-level tests).
func memTestServer() *Server {
	return &Server{
		memory: &memoryStore{
			Agents: map[string]*agentMemory{},
			Names:  map[string]string{},
			Prefs:  map[string]string{},
		},
		voice: newVoiceCtx(),
	}
}

func TestMemoryBindAndWhoIs(t *testing.T) {
	s := memTestServer()
	h, _, run, rep, _ := s.tryVoiceCmd(nil, "memory his name is Dave", "c1")
	if !h || run != "" {
		t.Fatalf("bind: handled=%v run=%q rep=%q (need host first)", h, run, rep)
	}
	if !strings.Contains(rep, "Select him first") {
		t.Fatalf("bind without host should ask for selection, got %q", rep)
	}
	// Simulate selected host by binding directly, then who-is.
	s.memoryMu.Lock()
	msg, ok := memBindName(s.memory, "dave", "DCHQHAK", func(string) bool { return true })
	s.memoryMu.Unlock()
	if !ok {
		t.Fatalf("bind refused: %s", msg)
	}
	h, _, run, rep, _ = s.tryVoiceCmd(nil, "voice-cmd who is Dave", "c2")
	if !h || run != "" || !strings.Contains(rep, "DCHQHAK") {
		t.Fatalf("whois: handled=%v run=%q rep=%q", h, run, rep)
	}
}

func TestMemoryBindCollision(t *testing.T) {
	s := memTestServer()
	s.memoryMu.Lock()
	_, ok := memBindName(s.memory, "dave", "BOXA", func(string) bool { return true })
	s.memoryMu.Unlock()
	if !ok {
		t.Fatal("first bind refused")
	}
	// Same name, other LIVE host: refused with re-point hint.
	s.memoryMu.Lock()
	msg, ok := memBindName(s.memory, "dave", "BOXB", func(h string) bool { return h == "BOXA" || h == "BOXB" })
	s.memoryMu.Unlock()
	if ok || !strings.Contains(msg, "means") {
		t.Fatalf("collision: ok=%v msg=%q", ok, msg)
	}
	// Other host OFFLINE: rebind allowed.
	s.memoryMu.Lock()
	msg, ok = memBindName(s.memory, "dave", "BOXB", func(h string) bool { return h == "BOXB" })
	s.memoryMu.Unlock()
	if !ok {
		t.Fatalf("offline-holder rebind refused: %s", msg)
	}
}

func TestMemoryBindStoplist(t *testing.T) {
	s := memTestServer()
	_, _, _, rep, _ := s.tryVoiceCmd(nil, "voice-cmd his name is history", "c1")
	if !strings.Contains(rep, "one of my own words") {
		t.Fatalf("stoplist: got %q", rep)
	}
}

func TestMemoryFactRoundTrip(t *testing.T) {
	s := memTestServer()
	// Scope needs a known name: bind it first.
	s.memoryMu.Lock()
	s.memory.Names["dave"] = "DCHQHAK"
	s.memoryMu.Unlock()
	h, _, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd remember he works nights about dave", "c2")
	if !h || run != "" || !strings.Contains(rep, "Noted") {
		t.Fatalf("fact: handled=%v run=%q rep=%q", h, run, rep)
	}
	h, _, run, rep, _ = s.tryVoiceCmd(nil, "voice-cmd what do you remember about dave", "c3")
	if !h || !strings.Contains(rep, "works nights") {
		t.Fatalf("recall: handled=%v rep=%q", h, rep)
	}
	// Fragment forget.
	h, _, run, rep, _ = s.tryVoiceCmd(nil, "voice-cmd forget nights about dave", "c4")
	if !h || !strings.Contains(rep, "Forgot 1") {
		t.Fatalf("forget: handled=%v rep=%q", h, rep)
	}
	// Verify gone from disk shape (in-memory store here).
	s.memoryMu.Lock()
	n := len(s.memory.Agents["DCHQHAK"].Facts)
	s.memoryMu.Unlock()
	if n != 0 {
		t.Fatalf("facts remain: %d", n)
	}
}

func TestMemoryWipeGate(t *testing.T) {
	s := memTestServer()
	s.memoryMu.Lock()
	s.memory.Names["dave"] = "DCHQHAK"
	s.memory.Agents["DCHQHAK"] = &agentMemory{Facts: []string{"works nights"}}
	s.memoryMu.Unlock()
	// Arm.
	_, _, _, rep, _ := s.tryVoiceCmd(nil, "voice-cmd forget everything about dave", "c1")
	if !strings.Contains(rep, "within a minute") {
		t.Fatalf("arm: %q", rep)
	}
	// Stray yes with nothing pending on a FRESH server: refused.
	s2 := memTestServer()
	_, _, _, rep2, _ := s2.tryVoiceCmd(nil, "voice-cmd yes", "c2")
	if !strings.Contains(rep2, "Nothing pending") {
		t.Fatalf("stray yes: %q", rep2)
	}
	// Confirm on the armed server.
	_, _, _, rep3, _ := s.tryVoiceCmd(nil, "voice-cmd yes", "c3")
	if !strings.Contains(rep3, "Forgot DCHQHAK") {
		t.Fatalf("confirm: %q", rep3)
	}
	s.memoryMu.Lock()
	_, haveFacts := s.memory.Agents["DCHQHAK"]
	_, haveName := s.memory.Names["dave"]
	s.memoryMu.Unlock()
	if haveFacts || haveName {
		t.Fatal("wipe left residue")
	}
}

func TestMemoryRepeatAndReplay(t *testing.T) {
	s := memTestServer()
	// Simulate a completed voice run.
	s.noteVoiceResult("c9", "1. Foo\n2. Bar", "")
	// noteVoiceResult without a preceding await is a no-op; register first.
	s.voiceMu.Lock()
	s.voice.awaiting["c9"] = &voicePending{text: "what tabs", run: "get-chrome-tabs", host: "DCHQHAK"}
	s.voiceMu.Unlock()
	s.noteVoiceResult("c9", "1. Foo\n2. Bar", "")
	_, _, _, rep, _ := s.tryVoiceCmd(nil, "voice-cmd what was that", "c10")
	if !strings.Contains(rep, "Foo") || !strings.Contains(rep, "Bar") {
		t.Fatalf("replay: %q", rep)
	}
}

func TestMemoryPrefs(t *testing.T) {
	s := memTestServer()
	_, _, _, rep, _ := s.tryVoiceCmd(nil, "voice-cmd remember my default agent is DCHQHAK", "c1")
	if !strings.Contains(rep, "defaultAgent") {
		t.Fatalf("pref: %q", rep)
	}
	_, _, _, rep, _ = s.tryVoiceCmd(nil, "voice-cmd remember call me boss", "c2")
	if !strings.Contains(rep, "callMe") {
		t.Fatalf("callme: %q", rep)
	}
	_, _, _, rep, _ = s.tryVoiceCmd(nil, "memory status", "c3")
	if !strings.Contains(rep, "defaultAgent=dchqhak") || !strings.Contains(rep, "callMe=boss") {
		t.Fatalf("status: %q", rep)
	}
}

func TestMemoryFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	old := memoryFilePath
	memoryFilePath = dir + "/memory.json"
	defer func() { memoryFilePath = old }()
	m := &memoryStore{
		Agents: map[string]*agentMemory{"H": {Name: "dave", Facts: []string{"x"}}},
		Names:  map[string]string{"dave": "H"},
		Prefs:  map[string]string{"callMe": "boss"},
	}
	saveMemoryFile(m)
	back := loadMemoryFile()
	if back.Names["dave"] != "H" || back.Prefs["callMe"] != "boss" || len(back.Agents["H"].Facts) != 1 {
		t.Fatalf("round trip: %+v", back)
	}
}

func TestMemoryGrammar(t *testing.T) {
	if _, ok := cutPrefixWord("forget", "forget"); !ok {
		t.Fatal("bare prefix")
	}
	if n, ok := parseForgetOrdinal("forget the third"); !ok || n != 3 {
		t.Fatalf("ordinal: %d %v", n, ok)
	}
	if n, ok := parseForgetOrdinal("forget 7"); !ok || n != 7 {
		t.Fatalf("digit: %d %v", n, ok)
	}
	if k, v, ok := parsePrefSet("remember that my default agent is BOX"); !ok || k != "default agent" || v != "BOX" {
		t.Fatalf("pref: %q %q %v", k, v, ok)
	}
	if n, ok := parseBindName("call him Dave"); !ok || n != "Dave" {
		t.Fatalf("bind: %q %v", n, ok)
	}
	if f, sc, ok := parseRememberFact("remember he works nights about dave"); !ok || f != "he works nights" || sc != "dave" {
		t.Fatalf("fact: %q %q %v", f, sc, ok)
	}
	if stripFillers("his wifi password") != "wifi password" {
		t.Fatal("fillers")
	}
}
