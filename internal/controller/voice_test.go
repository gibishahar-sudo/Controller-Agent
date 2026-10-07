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
