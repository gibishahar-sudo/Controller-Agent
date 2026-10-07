package controller

import (
	"strings"
	"testing"
)

// parseVoiceCmd is the whole NLU: a table pins every intent so Jarvis
// never silently changes meaning.
func TestParseVoiceCmd(t *testing.T) {
	cases := []struct {
		in      string
		handled bool
		run     string
		reply   string // substring; "" = expect no reply
	}{
		{"", true, "", "Yes?"},
		{"jarvis", true, "", "Yes?"},
		{"help", true, "", "what tabs"},
		{"Jarvis, WHAT TABS does he have?", true, "get-chrome-tabs", ""},
		{"what is he browsing right now", true, "get-chrome-tabs", ""},
		{"what is he doing right now", true, "get-active-window", ""},
		{"show me the active window", true, "get-active-window", ""},
		{"open his history on his pc", true, "open-url chrome chrome://history", ""},
		{"jarvis open his history over there", true, "open-url chrome chrome://history", ""},
		{"pull his search history", true, "get-chrome-history 20", ""},
		{"pull his search history for me", true, "get-chrome-history 20", ""},
		{"what can you do Jarvis", true, "", "what tabs"},
		{"open youtube Jarvis", true, "open-url chrome https://www.youtube.com", ""},
		{"what can i ask", true, "", "what tabs"},
		{"hey jarvis", true, "", "Yes?"},
		{"open youtube on his pc", true, "open-url chrome https://www.youtube.com", ""},
		{"jarvis open gmail", true, "open-url chrome https://mail.google.com", ""},
		{"open example.com", true, "open-url chrome https://example.com", ""},
		{"open", true, "", "Open what"},
		{"open that", true, "", "Open what"},
		{"open somewhere over the rainbow", true, "", "Don't know"},
		{"remember his name is Dave", true, "", "Say it fuller"},
		{"what do you remember about Dave", true, "", "Say it fuller"},
		{"forget his wifi password", true, "", "Say it fuller"},
		{"who is Dave", true, "", "Say it fuller"},
		{"open the third one", true, "", "Don't know"}, // ordinal + open: clarify wins over memory pointer
		{"open superman.com", true, "open-url chrome https://superman.com", ""}, // "up" must not eat the domain
		{"play that on his screen", false, "", ""},    // unknown: raw flow
		{"get-processes", false, "", ""},              // explicit raw vote
		{"rollout the red carpet", false, "", ""},     // garbage: raw flow (agent says unknown)
	}
	for _, c := range cases {
		h, run, rep := parseVoiceCmd(c.in, "DCHQHAK")
		if h != c.handled || run != c.run {
			t.Fatalf("input %q: got handled=%v run=%q, want %v %q (reply %q)", c.in, h, run, c.handled, c.run, rep)
		}
		if c.reply == "" && rep != "" {
			t.Fatalf("input %q: unexpected reply %q", c.in, rep)
		}
		if c.reply != "" && !strings.Contains(rep, c.reply) {
			t.Fatalf("input %q: reply %q lacks %q", c.in, rep, c.reply)
		}
		if rep != "" && !strings.HasPrefix(rep, "🎙 ") {
			t.Fatalf("input %q: reply missing mic prefix: %q", c.in, rep)
		}
	}
}

func TestParseVoiceCmdJarvisStrip(t *testing.T) {
	for _, in := range []string{"jarvis what tabs", "Jarvis, what tabs", "hey jarvis what tabs", "JARVIS  WHAT TABS"} {
		h, run, _ := parseVoiceCmd(in, "")
		if !h || run != "get-chrome-tabs" {
			t.Fatalf("strip %q: handled=%v run=%q", in, h, run)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := map[[2]string]int{
		{"1.46.82", "1.46.82"}: 0,
		{"1.46.69", "1.46.82"}: -1,
		{"1.46.83", "1.46.82"}: 1,
		{"", "1.46.72"}:        -1,
		{"garbage", "1.0.0"}:   -1,
		{"1.46", "1.46.0"}:     0,
		{"2.0", "1.99.99"}:     1,
	}
	for in, want := range cases {
		if got := compareVersions(in[0], in[1]); got != want {
			t.Fatalf("compare %q vs %q: got %d want %d", in[0], in[1], got, want)
		}
	}
}

func TestAgentTooOld(t *testing.T) {
	if !agentTooOld("1.46.69", "get-chrome-history 20") {
		t.Fatal(".69 must predate history")
	}
	if !agentTooOld("", "get-chrome-tabs") {
		t.Fatal("unknown version must count as old")
	}
	if agentTooOld("1.46.82", "get-chrome-history 20") {
		t.Fatal(".82 has history")
	}
	if agentTooOld("1.46.99", "get-active-window") {
		t.Fatal("unlisted verbs never gate")
	}
}

func TestSynthCommand(t *testing.T) {
	run, ok := synthCommand("1.46.69", "get-chrome-history 20")
	if !ok || !strings.HasPrefix(run, "run-powershell ") || !strings.Contains(run, "Select-Object -First 20") {
		t.Fatalf("history synth: ok=%v run=%q", ok, run)
	}
	run, ok = synthCommand("1.46.82", "get-chrome-history 20")
	if ok || run != "get-chrome-history 20" {
		t.Fatalf("current agent must pass through: %q", run)
	}
	run, ok = synthCommand("1.46.69", "get-chrome-tabs")
	if !ok || !strings.Contains(run, "MainWindowTitle") {
		t.Fatalf("tabs synth: ok=%v run=%q", ok, run)
	}
	if _, ok := synthCommand("1.40.0", "open-url chrome https://x.com"); ok {
		t.Fatal("ancient verbs must pass through")
	}
}

func TestOpNameAndBanks(t *testing.T) {	s := memTestServer()
	if got := s.opName(); got != "sir" {
		t.Fatalf("default address: %q", got)
	}
	s.memoryMu.Lock()
	s.memory.Prefs["callMe"] = "boss"
	s.memoryMu.Unlock()
	if got := s.opName(); got != "boss" {
		t.Fatalf("custom address: %q", got)
	}
	seen := map[string]bool{}
	for i := 0; i < len(jarvisAckBank); i++ {
		seen[jarvisPick(jarvisAckBank)] = true
	}
	if len(seen) != len(jarvisAckBank) {
		t.Fatal("ack bank must cycle without repeats")
	}
}

func TestVoiceSynthHook(t *testing.T) {
	s := memTestServer()
	old := &AgentConn{id: "a1", hostname: "OLD", version: "1.46.69"}
	h, _, run, _, _ := s.tryVoiceCmd(old, "voice-cmd pull his history", "c1")
	if !h || !strings.HasPrefix(run, "run-powershell ") {
		t.Fatalf("stale agent must get synthesis: handled=%v run=%q", h, run)
	}
	cur := &AgentConn{id: "a2", hostname: "NEW", version: "1.46.82"}
	h, _, run, _, _ = s.tryVoiceCmd(cur, "voice-cmd pull his history", "c2")
	if !h || run != "get-chrome-history 20" {
		t.Fatalf("current agent must keep canned: handled=%v run=%q", h, run)
	}
	oldTabs := &AgentConn{id: "a3", hostname: "OLD2", version: ""}
	h, _, run, _, _ = s.tryVoiceCmd(oldTabs, "voice-cmd what tabs", "c3")
	if !h || !strings.Contains(run, "MainWindowTitle") {
		t.Fatalf("unknown version must synthesize tabs: %q", run)
	}
}
