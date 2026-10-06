package controller

import (
	"fmt"
	"regexp"
	"strings"
)

// Jarvis voice/text commands (P1): "voice-cmd <what you said>" arrives as
// an ordinary command string over every ingress (WS console, /api/cmd for
// the tablet sender, local console) and is intercepted before sendToAgent,
// so no transport or protocol changes were needed. All matching is
// lowercase-contains on jarvis-stripped text; anything unmatched returns
// handled=false and flows on as a normal raw command (explicit operator
// vote: unknown phrases must run, not lecture).

// voiceSites fuzzy-matches spoken site names to URLs for "open X".
var voiceSites = map[string]string{
	"youtube":  "https://www.youtube.com",
	"gmail":    "https://mail.google.com",
	"facebook": "https://www.facebook.com",
	"whatsapp": "https://web.whatsapp.com",
	"google":   "https://www.google.com",
	"maps":     "https://maps.google.com",
	"drive":    "https://drive.google.com",
	"docs":     "https://docs.google.com",
	"github":   "https://github.com",
	"netflix":  "https://www.netflix.com",
	"spotify":  "https://open.spotify.com",
	"instagram": "https://www.instagram.com",
	"tiktok":   "https://www.tiktok.com",
	"amazon":   "https://www.amazon.com",
	"reddit":   "https://www.reddit.com",
	"bing":     "https://www.bing.com",
	"outlook":  "https://outlook.live.com",
	"chatgpt":  "https://chatgpt.com",
	"x":        "https://x.com",
	"twitter":  "https://x.com",
}

var jarvisPrefix = regexp.MustCompile(`^(hey[ ,]+)?jarvis([,. ]+|$)`)
var voiceSpaces = regexp.MustCompile(`\s+`)

// parseVoiceCmd maps operator text to an action. run = agent command to
// execute instead ("" = none); reply = direct operator text ("" = none).
// handled=false means "not a voice command shape at all / unknown" — the
// caller must pass the text on untouched.
func parseVoiceCmd(text, hostname string) (handled bool, run, reply string) {
	s := strings.ToLower(strings.TrimSpace(text))
	s = jarvisPrefix.ReplaceAllString(s, "")
	s = strings.TrimSpace(voiceSpaces.ReplaceAllString(s, " "))
	who := hostname
	if who == "" {
		who = "him"
	}
	say := func(t string) (bool, string, string) { return true, "", "🎙 "+t }

	if s == "" {
		return say("Yes? Tell me what to do — try: what tabs does he have.")
	}
	if s == "help" || s == "what can you do" || s == "commands" {
		return say("Try: what tabs does he have · what is he doing · open youtube on his pc · " +
			"open his history on his pc · voice-cmd anything else runs it raw. " +
			"History read-back and memory land next.")
	}
	// Memory verbs (P2): honest pointer, never a hallucinated yes.
	if hasAny(s, "remember", "recall", "what do you remember", "forget ", "forget his", "forget that", "who is ", "who's ", "whats his name", "what's his name", "his name") {
		return say("I can't keep notes yet — memory ships next. For now: tabs, activity, opening pages, or any raw command.")
	}
	// Ordinals without context (P2): no guessing.
	if hasAny(s, "first one", "second one", "third one", "fourth one", "fifth one", "that one", "those", "the other one") &&
		!hasAny(s, "open ", "pull", "history", "tabs") {
		return say("Numbered follow-ups arrive with memory — tell me the name or address for now.")
	}
	// History: remote-open wins on explicit place, else read-back pointer (P3).
	if strings.Contains(s, "histor") {
		if hasAny(s, "on his pc", "on his screen", "over there", " on there", " show him", "pull it up there") ||
			(strings.Contains(s, "there") && !strings.Contains(s, "for me") && !strings.Contains(s, "show me") && !strings.Contains(s, "tell me")) {
			return true, "open-url chrome chrome://history", ""
		}
		return say("History read-back ships next — say 'open his history on his pc' to open it on " + who + "'s screen now.")
	}
	// Tabs / browsing.
	if hasAny(s, "tab", "brows") {
		return true, "get-chrome-tabs", ""
	}
	// Live activity.
	if hasAny(s, "doing right now", "doing now", "active window", "foreground", "looking at", "working on") {
		return true, "get-active-window", ""
	}
	// Open a page (always remote — open-url only exists there).
	if s == "open" || strings.HasPrefix(s, "open ") {
		rest := strings.TrimSpace(strings.TrimPrefix(s, "open"))
		// Multiword place-noise first (distinctive phrases, no hazard),
		// then standalone filler tokens ("up" as substring would eat
		// "superman.com" — token-exact only).
		for _, noise := range []string{"on his pc", "on his screen", "over there", "for me"} {
			rest = strings.ReplaceAll(rest, noise, "")
		}
		var kept []string
		for _, tok := range strings.Fields(rest) {
			if tok == "please" || tok == "up" {
				continue
			}
			kept = append(kept, tok)
		}
		rest = strings.Join(kept, " ")
		if u, ok := voiceSites[rest]; ok {
			return true, "open-url chrome " + u, ""
		}
		if rest == "" || rest == "it" || rest == "that" {
			return say("Open what — name a site or paste a URL.")
		}
		if looksURL(rest) {
			return true, "open-url chrome " + ensureScheme(rest), ""
		}
		return say("Don't know '" + rest + "' — try a full address like example.com.")
	}
	return false, "", ""
}

func hasAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

var urlLike = regexp.MustCompile(`^([a-z0-9-]+\.)+[a-z]{2,}(/.*)?$|^localhost(:\d+)?(/.*)?$|^\d+\.\d+\.\d+\.\d+(:\d+)?(/.*)?$`)

func looksURL(s string) bool {
	s = strings.TrimSpace(s)
	if strings.Contains(s, " ") {
		return false
	}
	return urlLike.MatchString(strings.ToLower(s))
}

func ensureScheme(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "https://" + s
}

// tryVoiceCmd routes "voice-cmd <text>" pseudo-commands from any ingress.
// Direct replies are broadcast to all consoles (HTTP senders ignore bodies);
// run rewrites the agent command. Returns handled, run, reply (reply is for
// callers with a local screen, e.g. the stdin console).
func (s *Server) tryVoiceCmd(ac *AgentConn, cmd string) (handled bool, run, reply string) {
	t := strings.TrimSpace(cmd)
	if !strings.HasPrefix(strings.ToLower(t), "voice-cmd") {
		return false, "", ""
	}
	rest := strings.TrimSpace(t[len("voice-cmd"):])
	host := ""
	if ac != nil {
		host = ac.hostname
	}
	h, r, rep := parseVoiceCmd(rest, host)
	if !h {
		return false, "", ""
	}
	if rep != "" {
		s.broadcastWS(map[string]interface{}{"type": "output", "id": host, "data": rep, "success": true})
	}
	if r != "" {
		s.broadcastWS(map[string]interface{}{"type": "output", "id": host, "data": fmt.Sprintf("🎙 heard %q → %s", rest, r), "success": true})
	}
	return true, r, rep
}
