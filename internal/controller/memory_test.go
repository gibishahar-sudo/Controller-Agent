package controller

import (
	"strings"
	"testing"
	"time"
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

func TestMemoryGrammar(t *testing.T) {	if _, ok := cutPrefixWord("forget", "forget"); !ok {
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

func TestParseOrdinalRef(t *testing.T) {	cases := map[string]int{
		"open #2": 2, "open the second one": 2, "#3": 3, "7": 7,
		"number 2": 2, "2nd": 2, "open 1": 1, "the third one": 3,
		"second": 2, "third": 3,
	}
	for in, want := range cases {
		if n, ok := parseOrdinalRef(in); !ok || n != want {
			t.Fatalf("%q: got %d %v, want %d", in, n, ok, want)
		}
	}
	// Safety against stray numbers lives in ordinalOpen (fresh listable
	// lines required), not in the grammar — so only true non-ordinals
	// fail here.
	for _, in := range []string{"", "open", "forget 3", "abc", "#0", "open 0", "second helping"} {
		if n, ok := parseOrdinalRef(in); ok {
			t.Fatalf("%q must not parse (got %d)", in, n)
		}
	}
}

func TestHistoryRowURL(t *testing.T) {
	if u := historyRowURL("1. 2026-10-07 13:09 | Example | https://example.com/a"); u != "https://example.com/a" {
		t.Fatalf("row: %q", u)
	}
	if u := historyRowURL("profiles:"); u != "" {
		t.Fatalf("header: %q", u)
	}
	if u := historyRowURL("no pipes here"); u != "" {
		t.Fatalf("garbage: %q", u)
	}
}

func ordTestServer() *Server {
	s := memTestServer()
	s.agents = map[string]*AgentConn{"a1": {id: "a1", hostname: "DCHQHAK", version: "1.46.82"}}
	return s
}

func TestOrdinalOpenProfiles(t *testing.T) {
	s := ordTestServer()
	s.voice.last = &voiceResult{
		run:   "get-chrome-history 20",
		lines: []string{"profiles:", "1. Personal (dave@gmail) [Default]", "2. Work [Profile 1]"},
		host:  "DCHQHAK", at: time.Now(),
	}
	h, tac, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd open the second one", "c1")
	if !h || run != "get-chrome-history 20 #2" || tac == nil || tac.hostname != "DCHQHAK" {
		t.Fatalf("profiles ordinal: handled=%v run=%q tac=%v rep=%q", h, run, tac, rep)
	}
	h, _, run, rep, _ = s.tryVoiceCmd(nil, "voice-cmd open 9", "c2")
	if !h || run != "" || !strings.Contains(rep, "Only 2") {
		t.Fatalf("out of range: handled=%v run=%q rep=%q", h, run, rep)
	}
}

func TestOrdinalOpenHistory(t *testing.T) {
	s := ordTestServer()
	s.voice.last = &voiceResult{
		run: "get-chrome-history 20",
		lines: []string{
			"1. 2026-10-07 13:09 | A | https://a.example/x",
			"2. 2026-10-07 13:08 | B | https://b.example/y",
		},
		host: "DCHQHAK", at: time.Now(),
	}
	h, tac, run, _, _ := s.tryVoiceCmd(nil, "voice-cmd open 1", "c1")
	if !h || run != "open-url chrome https://a.example/x" || tac == nil {
		t.Fatalf("history ordinal: handled=%v run=%q", h, run)
	}
}

func TestOrdinalStaleFallsThrough(t *testing.T) {
	s := ordTestServer()
	s.voice.last = &voiceResult{run: "x", lines: []string{"1. A | https://a.example"}, host: "DCHQHAK", at: time.Now().Add(-time.Hour)}
	h, _, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd open 1", "c1")
	if !h || run != "" {
		t.Fatalf("stale must not run: handled=%v run=%q rep=%q", h, run, rep)
	}
}

func TestOrdinalOfflineBox(t *testing.T) {
	s := memTestServer() // no agents map: box offline
	s.voice.last = &voiceResult{
		run: "get-chrome-history 20",
		lines: []string{"profiles:", "1. Personal [Default]"},
		host:  "DCHQHAK", at: time.Now(),
	}
	h, _, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd open 1", "c1")
	if !h || run != "" || !strings.Contains(rep, "offline") {
		t.Fatalf("offline: handled=%v run=%q rep=%q", h, run, rep)
	}
}

func TestProfileLineNames(t *testing.T) {
	got := profileLineNames("1. Personal (dave@gmail) [Default]")
	want := map[string]bool{"Personal": true, "Default": true, "dave@gmail": true, "dave": true}
	if len(got) != len(want) {
		t.Fatalf("tokens = %v", got)
	}
	for _, c := range got {
		if !want[c] {
			t.Fatalf("unexpected token %q in %v", c, got)
		}
	}
	got = profileLineNames("2. Work [Profile 1]")
	for _, w := range []string{"Work", "Profile 1"} {
		found := false
		for _, c := range got {
			if c == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q missing in %v", w, got)
		}
	}
}

func TestProfileNameRef(t *testing.T) {
	rows := []string{"1. Personal (dave@gmail) [Default]", "2. Work [Profile 1]"}
	if n, ok := profileNameRef("open work", rows); !ok || n != "Work" {
		t.Fatalf("work: %q %v", n, ok)
	}
	if n, ok := profileNameRef("personal please", rows); !ok || n != "Personal" {
		t.Fatalf("personal: %q %v", n, ok)
	}
	if n, ok := profileNameRef("the work profile", rows); !ok || n != "Work" {
		t.Fatalf("work profile: %q %v", n, ok)
	}
	// Token boundary: "network" must not match "work".
	if _, ok := profileNameRef("network issues", rows); ok {
		t.Fatal("network must not match work")
	}
	if _, ok := profileNameRef("something else entirely", rows); ok {
		t.Fatal("no match expected")
	}
}

func TestProfileNameOpen(t *testing.T) {
	s := ordTestServer()
	s.voice.last = &voiceResult{
		run:   "get-chrome-history 20",
		lines: []string{"profiles:", "1. Personal (dave@gmail) [Default]", "2. Work [Profile 1]"},
		host:  "DCHQHAK", at: time.Now(),
	}
	h, tac, run, _, _ := s.tryVoiceCmd(nil, "voice-cmd open work", "c1")
	if !h || run != "get-chrome-history 20 Work" || tac == nil {
		t.Fatalf("name open: handled=%v run=%q", h, run)
	}
	h, _, run, _, _ = s.tryVoiceCmd(nil, "voice-cmd zzz qq", "c2")
	if !h || run != "" {
		t.Fatalf("unmatched name must not run: handled=%v run=%q", h, run)
	}
}

func TestHistorySearchRows(t *testing.T) {
	lines := []string{
		"1. 2026-10-07 | Cats | https://example.com/cats",
		"2. 2026-10-07 | Search | https://www.google.com/search?q=cats",
		"3. 2026-10-07 | B | https://b.example/y?x=1",
		"no url here",
		"4. 2026-10-07 | D | https://duckduckgo.com/?q=dogs",
	}
	got := historySearchRows(lines)
	if len(got) != 2 || !strings.Contains(got[0], "google") || !strings.Contains(got[1], "duckduckgo") {
		t.Fatalf("search filter = %v", got)
	}
}

func TestHistorySearchesReply(t *testing.T) {
	s := ordTestServer()
	_, _, _, rep, _ := s.tryVoiceCmd(nil, "voice-cmd only searches", "c0")
	if !strings.Contains(rep, "Pull his history first") {
		t.Fatalf("no history: %q", rep)
	}
	s.voice.last = &voiceResult{
		run: "get-chrome-history 40", text: "pull his search history",
		lines: []string{
			"1. A | https://a.example/x",
			"2. S | https://www.google.com/search?q=a",
		},
		host: "DCHQHAK", at: time.Now(),
	}
	_, _, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd only searches", "c1")
	if run != "" || !strings.Contains(rep, "google") || strings.Contains(rep, "a.example") {
		t.Fatalf("filtered: run=%q rep=%q", run, rep)
	}
	s.voice.last.lines = []string{"1. A | https://a.example/x"}
	_, _, _, rep, _ = s.tryVoiceCmd(nil, "voice-cmd only searches", "c2")
	if !strings.Contains(rep, "No searches") {
		t.Fatalf("empty filter: %q", rep)
	}
}

func TestExportFlow(t *testing.T) {
	s := ordTestServer()
	s.agents["a1"] = &AgentConn{id: "a1", hostname: "DCHQHAK", user: "Admin", version: "1.46.92"}
	ac := &AgentConn{id: "a1", hostname: "DCHQHAK", user: "Admin", version: "1.46.92"}
	_, _, run, _, eff := s.tryVoiceCmd(ac, "voice-cmd pull his history", "e0")
	if run == "" || eff == "" {
		t.Fatalf("history must run: %q", run)
	}
	s.noteVoiceResult(eff, "1. A | https://a.example/x\n2. B | https://b.example/y", "")
	h, _, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd yes", "e1")
	if !h || !strings.HasPrefix(run, "write-file ") || !strings.Contains(run, ".txt|") {
		t.Fatalf("yes must export: handled=%v run=%q rep=%q", h, run, rep)
	}
	if !strings.Contains(run, `C:\Users\Admin\Desktop\history-dchqhak-`) {
		t.Fatalf("desktop path: %q", run)
	}
	if !strings.Contains(rep, "2 rows") {
		t.Fatalf("ack: %q", rep)
	}
	// Offer is single-use: second yes falls to wipe confirm (nothing armed).
	_, _, _, rep, _ = s.tryVoiceCmd(nil, "voice-cmd yes", "e2")
	if !strings.Contains(rep, "Nothing pending") {
		t.Fatalf("second yes: %q", rep)
	}
}

func TestExportNameSanitize(t *testing.T) {
	if got := exportFileName("DCHQHAK!", time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)); got != "history-dchqhak-20261009-010203.txt" {
		t.Fatalf("name: %q", got)
	}
	if got := exportFileName("!!!", time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)); !strings.HasPrefix(got, "history-history-") {
		t.Fatalf("empty host fallback: %q", got)
	}
}

func TestExportWipeTie(t *testing.T) {
	s := ordTestServer()
	s.agents["a1"] = &AgentConn{id: "a1", hostname: "DCHQHAK", user: "Admin", version: "1.46.92"}
	s.voice.pendingExport = &voiceExport{host: "DCHQHAK", user: "Admin", lines: []string{"1. A | https://a.example"}, at: time.Now()}
	s.voice.exportAt = time.Now()
	s.voice.pendingWipe = "everything"
	s.voice.pendingAt = time.Now()
	_, _, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd yes", "c1")
	if run != "" || !strings.Contains(rep, "wipe AND a txt export") {
		t.Fatalf("tie must clarify, never destroy: run=%q rep=%q", run, rep)
	}
	_, _, run, rep, _ = s.tryVoiceCmd(nil, "voice-cmd export it", "c2")
	if !strings.HasPrefix(run, "write-file ") {
		t.Fatalf("explicit export: run=%q rep=%q", run, rep)
	}
}

func TestVoiceMissNeverForwards(t *testing.T) {
	s := ordTestServer()
	for _, in := range []string{"voice-cmd taylor 11 seconds to a", "voice-cmd a lot of his suitcase terry", "voice-cmd pull up a 6 to 3", "voice-cmd zzz qq"} {
		h, _, run, rep, _ := s.tryVoiceCmd(nil, in, "c9")
		if !h || run != "" || !strings.Contains(rep, "Didn't catch that") {
			t.Fatalf("%q: handled=%v run=%q rep=%q", in, h, run, rep)
		}
	}
	h, _, run, rep, _ := s.tryVoiceCmd(nil, "memory zzz frobnicate", "c8")
	if !h || run != "" || !strings.Contains(rep, "Memory didn't parse") {
		t.Fatalf("memory miss: handled=%v run=%q rep=%q", h, run, rep)
	}
}

func TestSuggestIntents(t *testing.T) {
	if got := suggestIntents("pull up the thing"); len(got) == 0 || got[0] != "pull his history" {
		t.Fatalf("pull: %v", got)
	}
	if got := suggestIntents("zzz qq 123"); len(got) != 0 {
		t.Fatalf("gibberish: %v", got)
	}
	if got := suggestIntents("open youtube please"); len(got) == 0 || got[0] != "open a page" {
		t.Fatalf("open: %v", got)
	}
}

func TestPickVoiceReply(t *testing.T) {
	s := memTestServer()
	if _, _, ok := s.pickVoiceReply(0); ok {
		t.Fatal("empty must miss")
	}
	now := time.Now()
	s.voice.spoken = &voiceSpoken{text: "hello there", at: now.Add(-time.Minute)}
	if text, _, ok := s.pickVoiceReply(0); !ok || text != "hello there" {
		t.Fatalf("spoken: %q %v", text, ok)
	}
	if _, _, ok := s.pickVoiceReply(now.Add(time.Minute).UnixMilli()); ok {
		t.Fatal("future since must miss")
	}
	// Newer run result wins over older direct reply.
	s.voice.last = &voiceResult{run: "get-chrome-tabs", lines: []string{"1. Foo", "2. Bar"}, host: "H", at: now}
	if text, _, ok := s.pickVoiceReply(0); !ok || text != "1. Foo · 2. Bar" {
		t.Fatalf("run lines: %q %v", text, ok)
	}
}

func TestFinishVoiceStashesSpoken(t *testing.T) {
	s := memTestServer()
	h, _, run, rep, _ := s.tryVoiceCmd(nil, "voice-cmd help", "c1")
	if !h || run != "" || rep == "" {
		t.Fatalf("help: handled=%v run=%q rep=%q", h, run, rep)
	}
	if text, _, ok := s.pickVoiceReply(0); !ok || text != rep {
		t.Fatalf("stash: %q %v want %q", text, ok, rep)
	}
}

func TestVoiceRunFailed(t *testing.T) {
	for _, s := range []string{
		"'get-chrome-history' is not recognized as an internal or external command,",
		"The term 'foo' is not recognized as the name of a cmdlet,",
		"unknown command: frobnicate",
	} {
		if !voiceRunFailed(s) {
			t.Fatalf("should flag failure: %q", s)
		}
	}
	// Transport errors ride the errStr branch of noteVoiceResult, not text.
	for _, s := range []string{"3 Chrome window(s):\n1. Foo", "ok", ""} {
		if voiceRunFailed(s) {
			t.Fatalf("false positive: %q", s)
		}
	}
}

func TestDayGreeting(t *testing.T) {
	cases := map[int]string{
		0: "Burning the midnight oil", 4: "Burning the midnight oil",
		5: "Good morning", 11: "Good morning",
		12: "Good afternoon", 17: "Good afternoon",
		18: "Good evening", 22: "Good evening", 23: "Burning the midnight oil",
	}
	for h, want := range cases {
		if got := dayGreeting(h); got != want {
			t.Fatalf("hour %d: got %q want %q", h, got, want)
		}
	}
}

func TestIsHelpRequest(t *testing.T) {
	for _, s := range []string{"help", "what can you do", "commands", "what can i ask", "help me", "what do you do"} {
		if !isHelpRequest(s) {
			t.Fatalf("%q must be help", s)
		}
	}
	if isHelpRequest("help yourself") || isHelpRequest("helper") {
		t.Fatal("prefix bleed")
	}
}

func TestHelpNamesKnown(t *testing.T) {
	s := memTestServer()
	s.memoryMu.Lock()
	s.memory.Names["dave"] = "DCHQHAK"
	s.memoryMu.Unlock()
	_, _, _, rep, _ := s.tryVoiceCmd(nil, "voice-cmd help", "c1")
	if !strings.Contains(rep, "I know dave (DCHQHAK)") {
		t.Fatalf("help must name names: %q", rep)
	}
	if !strings.Contains(rep, "what tabs") {
		t.Fatalf("help must keep the list: %q", rep)
	}
}

func TestKnownNames(t *testing.T) {
	s := memTestServer()
	if got := s.knownNames(); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
	s.memoryMu.Lock()
	s.memory.Names["zed"] = "H2"
	s.memory.Names["amy"] = "H1"
	s.memoryMu.Unlock()
	got := s.knownNames()
	if len(got) != 2 || got[0] != "amy (H1)" || got[1] != "zed (H2)" {
		t.Fatalf("sorted pairs: %v", got)
	}
}

// dupAlarmText names the host, the count, and caps the id list.
func TestDupAlarmText(t *testing.T) {
	got := dupAlarmText("H", []string{"b", "a"})
	if !strings.Contains(got, "2 agents on H") || !strings.Contains(got, "a, b") {
		t.Fatalf("shape: %q", got)
	}
	many := []string{"1", "2", "3", "4", "5", "6", "7"}
	got = dupAlarmText("H", many)
	if !strings.Contains(got, "7 agents on H") || !strings.Contains(got, "…") || strings.Contains(got, "7, ") {
		t.Fatalf("truncate: %q", got)
	}
}

// dupCheck alarms once at threshold, re-fires on growth, clears below.
func TestDupCheck(t *testing.T) {
	s := memTestServer()
	s.agents = map[string]*AgentConn{}
	add := func(id string) {
		s.agentsMu.Lock()
		s.agents[id] = &AgentConn{hostname: "H", id: id}
		s.agentsMu.Unlock()
		s.dupCheck("H")
	}
	add("a1")
	add("a2")
	if len(s.dupAlarmed) != 0 {
		t.Fatal("below threshold must stay silent")
	}
	add("a3")
	if s.dupAlarmed["H"] != 3 {
		t.Fatalf("threshold must alarm: %v", s.dupAlarmed)
	}
	add("a4")
	if s.dupAlarmed["H"] != 4 {
		t.Fatalf("growth must re-fire: %v", s.dupAlarmed)
	}
	s.agentsMu.Lock()
	delete(s.agents, "a4")
	delete(s.agents, "a3")
	s.agentsMu.Unlock()
	s.dupCheck("H")
	if len(s.dupAlarmed) != 0 {
		t.Fatalf("drop below threshold must clear: %v", s.dupAlarmed)
	}
	s.dupCheck("")
}
