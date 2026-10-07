package controller

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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
var jarvisSuffix = regexp.MustCompile(`[, ]*\bjarvis[?!.]*$`)
var voiceSpaces = regexp.MustCompile(`\s+`)

// normVoice lowercases, strips an optional jarvis prefix AND a trailing
// jarvis ("what can you do Jarvis" must parse — the name comes last in
// speech), and squeezes whitespace. Shared by intents and memory grammar.
func normVoice(text string) string {
	s := strings.ToLower(strings.TrimSpace(text))
	s = jarvisPrefix.ReplaceAllString(s, "")
	s = jarvisSuffix.ReplaceAllString(s, "")
	return strings.TrimSpace(voiceSpaces.ReplaceAllString(s, " "))
}

// isVoiceCmd reports the operator pseudo-command prefixes (voice-cmd for
// speech-or-text, memory for typed memory ops). The agent never sees these.
func isVoiceCmd(cmd string) bool {
	t := strings.ToLower(strings.TrimSpace(cmd))
	return strings.HasPrefix(t, "voice-cmd") || t == "memory" || strings.HasPrefix(t, "memory ")
}

// parseVoiceCmd maps operator text to an action. run = agent command to
// execute instead ("" = none); reply = direct operator text ("" = none).
// handled=false means "not a voice command shape at all / unknown" — the
// caller must pass the text on untouched.
func parseVoiceCmd(text, hostname string) (handled bool, run, reply string) {
	s := normVoice(text)
	_ = hostname // selection only matters for memory retargeting (tryVoiceCmd layer)
	say := func(t string) (bool, string, string) { return true, "", "🎙 "+t }

	if s == "" {
		return say("Yes? Tell me what to do — try: what tabs does he have.")
	}
	if s == "help" || s == "what can you do" || s == "commands" || s == "what can i ask" || s == "help me" || s == "what do you do" {
		return say("Try: what tabs does he have · pull his history · open youtube on his pc · " +
			"remember his name is Dave · memory status · voice-cmd anything else runs it raw.")
	}
	// Memory verbs that didn't parse as memory grammar (too short or
	// mangled): point at the working forms, never pretend otherwise.
	if hasAny(s, "remember", "recall", "what do you remember", "forget ", "forget his", "forget that", "who is ", "who's ", "whats his name", "what's his name", "his name") {
		return say("Say it fuller: 'remember <fact>', 'what do you remember?', 'forget <word>', 'who is <name>' — or 'memory status'.")
	}
	// Bare ordinals with no listing behind them.
	if hasAny(s, "first one", "second one", "third one", "fourth one", "fifth one", "that one", "those", "the other one") &&
		!hasAny(s, "open ", "pull", "history", "tabs") {
		return say("Numbered picks work after a listing — 'what do you remember?', then 'forget 2'.")
	}
	// History: remote-open wins on explicit place, else read-back from the
	// agent (his box, his profiles).
	if strings.Contains(s, "histor") {
		if hasAny(s, "on his pc", "on his screen", "over there", " on there", " show him", "pull it up there") ||
			(strings.Contains(s, "there") && !strings.Contains(s, "for me") && !strings.Contains(s, "show me") && !strings.Contains(s, "tell me")) {
			return true, "open-url chrome chrome://history", ""
		}
		return true, "get-chrome-history 20", ""
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

// pickVoiceReply returns the newest voice answer (direct reply or completed
// run result) newer than sinceMillis, for the tablet TTS poll. 204-style
// miss is reported as ok=false.
func (s *Server) pickVoiceReply(sinceMillis int64) (text string, ts int64, ok bool) {
	s.voiceMu.Lock()
	defer s.voiceMu.Unlock()
	var best string
	var bestTs int64
	if sp := s.voice.spoken; sp != nil {
		if t := sp.at.UnixMilli(); t > sinceMillis && t > bestTs {
			best, bestTs = sp.text, t
		}
	}
	if last := s.voice.last; last != nil && len(last.lines) > 0 {
		if t := last.at.UnixMilli(); t > sinceMillis && t > bestTs {
			best, bestTs = strings.Join(last.lines, " · "), t
		}
	}
	if bestTs == 0 {
		return "", 0, false
	}
	return best, bestTs, true
}

// parseMemoryCmd handles the memory grammar (shared by voice-cmd memory
// phrases and the memory pseudo-command). host = selected hostname ("" if
// none). Returns matched, and optionally tac to retarget execution.
// viaMemory distinguishes "memory <sub>" (bare status/help allowed) from
// voice flow. Anything unmatched returns false so voice flow continues to
// P1 intents (or raw), and memory flow falls through to the agent.
func (s *Server) parseMemoryCmd(text, host string, viaMemory bool) (bool, *AgentConn, string, string) {
	sn := normVoice(text)
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }

	if sn == "" {
		if viaMemory {
			return say(s.memorySummary())
		}
		return say("Yes? Tell me what to do — try: what tabs does he have.")
	}
	// Wipe confirm.
	if sn == "yes" || sn == "yeah" || sn == "yep" || sn == "do it" || sn == "confirm" || sn == "wipe it" {
		return s.memoryWipeConfirm()
	}
	// Arm wipe.
	if rest, ok := cutPrefixWord(sn, "forget everything"); ok {
		return s.memoryWipeArm(strings.TrimSpace(strings.TrimPrefix(rest, "about ")))
	}
	// Ordinal forget against the last facts listing.
	if n, ok := parseForgetOrdinal(sn); ok {
		return s.memoryForgetIndex(n)
	}
	// Fragment forget.
	if rest, ok := cutPrefixWord(sn, "forget"); ok {
		return s.memoryForgetFrag(rest, host)
	}
	// Prefs: my <k> is <v>.
	if k, v, ok := parsePrefSet(sn); ok {
		return s.memorySetPref(k, v)
	}
	// Name binding.
	if name, ok := parseBindName(sn); ok {
		return s.memoryBind(name, host)
	}
	// Re-point: X means Y.
	if name, href, ok := parseMeans(sn); ok {
		return s.memoryRepoint(name, href)
	}
	// Fact append.
	if fact, scope, ok := parseRememberFact(sn); ok {
		return s.memoryAddFact(fact, scope, host)
	}
	// Recall.
	if scope, ok := parseRecall(sn); ok {
		return s.memoryRecall(scope, host)
	}
	// Who-is.
	if name, ok := parseWhoIs(sn); ok {
		return s.memoryWhoIs(name)
	}
	// Repeat last run.
	if sn == "again" || sn == "once more" || sn == "repeat that" || sn == "one more time" || sn == "do it again" || sn == "run it again" {
		return s.memoryRepeat()
	}
	// Recall cached result text.
	if sn == "what was that" || sn == "say again" || sn == "repeat what you said" || sn == "show that again" {
		return s.memoryReplay()
	}
	// Memory status (memory-prefix only; bare "status" in voice flow means
	// the agent's get-status via P1).
	if viaMemory && (sn == "status" || sn == "help") {
		return say(s.memorySummary())
	}
	return false, nil, "", ""
}
// pseudo-commands from any ingress. Memory grammar runs first (names,
// facts, prefs, recall, wipe gate, repeats); P1 intents after. Direct
// replies broadcast to all consoles; run rewrites the agent command on
// tac (retargeted by name when spoken, else the selected agent).
func (s *Server) tryVoiceCmd(ac *AgentConn, cmd, cmdID string) (handled bool, tac *AgentConn, run, reply, effID string) {
	t := strings.TrimSpace(cmd)
	lt := strings.ToLower(t)
	isVoice := strings.HasPrefix(lt, "voice-cmd")
	isMem := lt == "memory" || strings.HasPrefix(lt, "memory ")
	if !isVoice && !isMem {
		return false, nil, "", "", ""
	}
	rest := ""
	if isVoice {
		rest = strings.TrimSpace(t[len("voice-cmd"):])
	} else {
		rest = strings.TrimSpace(t[len("memory"):])
	}
	host := ""
	if ac != nil {
		host = ac.hostname
	}
	if h, tac2, run2, rep := s.parseMemoryCmd(rest, host, isMem); h {
		return s.finishVoice(ac, tac2, run2, rep, rest, cmdID)
	}
	// Ordinal follow-ups against the freshest listable result (profiles →
	// re-pull with #N; history rows → open the Nth URL). Runs on the box
	// that produced the listing.
	if n, ok := parseOrdinalRef(normVoice(rest)); ok {
		if tac, run, rep, matched := s.ordinalOpen(n); matched {
			return s.finishVoice(ac, tac, run, rep, rest, cmdID)
		}
	}
	if !isVoice {
		return false, nil, "", "", ""
	}
	h, r, rep := parseVoiceCmd(rest, host)
	if !h {
		return false, nil, "", "", ""
	}
	if r != "" {
		if tac2, note := s.retargetByName(rest, ac); note != "" {
			return true, ac, "", "🎙 " + note, effIDFor(cmdID)
		} else if tac2 != nil && tac2 != ac {
			ac = tac2
		}
	}
	return s.finishVoice(ac, ac, r, rep, rest, cmdID)
}

// finishVoice registers context tracking, broadcasts replies, and mints
// the effective command id (fresh when the caller had none, so console
// voice runs join CmdID-tracked results like everyone else).
func (s *Server) finishVoice(ac, tac *AgentConn, run, rep, rest, cmdID string) (bool, *AgentConn, string, string, string) {
	effID := cmdID
	if effID == "" {
		effID = fmt.Sprintf("v%x", time.Now().UnixNano())
	}
	host := ""
	if tac != nil {
		host = tac.hostname
	}
	if rep != "" {
		// Phrasing wire (P0r-proven job): replies get one llmSay pass,
		// but ONLY when the sidecar is already warm — never a pull,
		// never added latency hunting one. Failures keep the raw text.
		// Threshold lowered from 80 to 40: most useful replies are short.
		if len(rep) > 40 {
			if line, ok := s.llmPhraseIfReady(rep); ok {
				rep = line
			}
		}
		s.broadcastWS(map[string]interface{}{"type": "output", "id": host, "data": rep, "success": true})
		s.voiceMu.Lock()
		s.voice.spoken = &voiceSpoken{text: rep, at: time.Now()}
		s.voiceMu.Unlock()
	}
	if run != "" {
		if tac == nil {
			tac = ac
		}
		s.voiceMu.Lock()
		s.voice.awaiting[effID] = &voicePending{text: rest, run: run, host: host, ts: time.Now()}
		s.voiceMu.Unlock()
		s.broadcastWS(map[string]interface{}{"type": "output", "id": host, "data": fmt.Sprintf("🎙 heard %q → %s", rest, run), "success": true})
		return true, tac, run, rep, effID
	}
	return true, tac, "", rep, effID
}

func effIDFor(cmdID string) string {
	if cmdID != "" {
		return cmdID
	}
	return fmt.Sprintf("v%x", time.Now().UnixNano())
}

// --- memory verbs (P2) ---

const wipeTTL = 60 * time.Second

// voiceNameStop stops binding reserved words as names (they'd hijack
// retarget matching: a name "history" would fire on "pull his history").
var voiceNameStop = map[string]bool{
	"me": true, "my": true, "him": true, "his": true, "her": true,
	"you": true, "there": true, "here": true, "it": true, "that": true,
	"this": true, "them": true, "us": true, "we": true, "i": true,
	"history": true, "tabs": true, "tab": true, "open": true,
	"remember": true, "recall": true, "forget": true, "who": true,
	"again": true, "yes": true, "help": true, "status": true,
	"memory": true, "voice": true, "jarvis": true, "agent": true,
	"pc": true, "screen": true, "run": true, "list": true, "show": true,
	"all": true, "everything": true, "number": true, "one": true,
}

func (s *Server) memoryWipeConfirm() (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	s.voiceMu.Lock()
	scope := s.voice.pendingWipe
	fresh := scope != "" && time.Since(s.voice.pendingAt) < wipeTTL
	if fresh {
		s.voice.pendingWipe = ""
	}
	s.voiceMu.Unlock()
	if !fresh {
		return say("Nothing pending — say 'forget everything' first, then 'yes' within a minute.")
	}
	s.memoryMu.Lock()
	defer func() { saveMemoryFile(s.memory); s.memoryMu.Unlock() }()
	if scope == "everything" {
		names, facts := len(s.memory.Names), 0
		for _, am := range s.memory.Agents {
			facts += len(am.Facts)
		}
		s.memory.Agents = map[string]*agentMemory{}
		s.memory.Names = map[string]string{}
		return say(fmt.Sprintf("Forgot everything (%d names, %d facts). Your preferences are kept.", names, facts))
	}
	host := strings.TrimPrefix(scope, "agent:")
	n := memWipeAgent(s.memory, host)
	return say(fmt.Sprintf("Forgot %s (%d item(s)).", host, n))
}

func (s *Server) memoryWipeArm(scope string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	desc := "everything"
	key := "everything"
	if scope != "" && scope != "everything" && scope != "all" {
		host, ok := s.memoryScopeHost(scope)
		if !ok {
			return say("Wipe what? I don't know '" + scope + "'.")
		}
		key, desc = "agent:"+host, host
	}
	s.voiceMu.Lock()
	s.voice.pendingWipe = key
	s.voice.pendingAt = time.Now()
	s.voiceMu.Unlock()
	return say(fmt.Sprintf("Say 'voice-cmd yes' within a minute to wipe %s. Preferences are kept.", desc))
}

func (s *Server) memoryForgetIndex(n int) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	s.voiceMu.Lock()
	rec := s.voice.recall
	fresh := s.voiceFresh(rec)
	s.voiceMu.Unlock()
	if !fresh || len(rec.lines) == 0 {
		return say("List facts first — 'what do you remember?' — then 'forget' the number.")
	}
	if n < 1 || n > len(rec.lines) {
		return say(fmt.Sprintf("Only %d facts listed — forget 1 to %d.", len(rec.lines), len(rec.lines)))
	}
	// Recall lines render as "N. fact" — strip the ordinal back off.
	want := strings.TrimSpace(rec.lines[n-1])
	if i := strings.Index(want, ". "); i > 0 && i < 6 {
		want = strings.TrimSpace(want[i+2:])
	}
	s.memoryMu.Lock()
	defer func() { saveMemoryFile(s.memory); s.memoryMu.Unlock() }()
	deleted := memForgetFragment(s.memory, rec.host, want)
	if len(deleted) == 0 {
		// Fallback: exact full-line match (fact text may have shifted).
		return say("That one is already gone.")
	}
	return say(fmt.Sprintf("Forgot: %s", want))
}

func (s *Server) memoryForgetFrag(rest, host string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	frag, scope := splitAbout(rest)
	frag = stripFillers(frag)
	if frag == "" {
		return say("Forget what, exactly?")
	}
	var scopeHost string
	if scope != "" {
		h, ok := s.memoryScopeHost(scope)
		if !ok {
			return say("I don't know '" + scope + "' — about whom?")
		}
		scopeHost = h
	} else if host != "" {
		scopeHost = host
	}
	s.memoryMu.Lock()
	defer func() { saveMemoryFile(s.memory); s.memoryMu.Unlock() }()
	if scopeHost == "" {
		// No scope anywhere: search all, list, delete nothing.
		var hits []string
		for h, am := range s.memory.Agents {
			for _, f := range am.Facts {
				if strings.Contains(strings.ToLower(f), strings.ToLower(frag)) {
					hits = append(hits, h+": "+f)
				}
			}
		}
		sort.Strings(hits)
		if len(hits) == 0 {
			return say("Nothing matching '" + frag + "' anywhere.")
		}
		return say("Matches (say which host's to forget): " + strings.Join(hits, " · "))
	}
	deleted := memForgetFragment(s.memory, scopeHost, frag)
	if len(deleted) == 0 {
		return say(fmt.Sprintf("Nothing on %s matches '%s'.", scopeHost, frag))
	}
	return say(fmt.Sprintf("Forgot %d: %s", len(deleted), strings.Join(deleted, " · ")))
}

func (s *Server) memorySetPref(k, v string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	var key, val, note string
	switch {
	case strings.Contains(k, "default agent"):
		vv := strings.TrimSpace(v)
		if vv == "" {
			return say("Default agent to what — name a box?")
		}
		// Store first, resolve at use: the box may be offline right now
		// (or not yet seen). Prefer a known hostname when recognizable.
		key, val, note = "defaultAgent", vv, "will use when online"
		if h, ok := s.resolvePrefHost(vv); ok {
			val, note = h, "using "+h
		}
	case strings.Contains(k, "reply aloud") || strings.Contains(k, "read aloud") || k == "speak" || k == "talk":
		vv := strings.ToLower(strings.TrimSpace(v))
		val = "off"
		if vv == "" || strings.Contains(vv, "on") || strings.Contains(vv, "yes") || strings.Contains(vv, "always") || strings.Contains(vv, "true") || strings.Contains(vv, "enabl") {
			val = "on" // bare "reply aloud" means enable
		}
		key = "replyAloud"
	case strings.Contains(k, "call me"):
		if strings.TrimSpace(v) == "" {
			return say("Call you what?")
		}
		key, val = "callMe", strings.TrimSpace(v)
	default:
		return say("I keep: default agent, reply aloud (on/off), call me <name>.")
	}
	s.memoryMu.Lock()
	s.memory.Prefs[key] = val
	saveMemoryFile(s.memory)
	s.memoryMu.Unlock()
	if note != "" {
		return say(fmt.Sprintf("Noted: %s %s (%s).", key, val, note))
	}
	return say(fmt.Sprintf("Noted: %s is %s.", key, val))
}

func (s *Server) memoryBind(name, host string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	name = strings.ToLower(strings.TrimSpace(name))
	if voiceNameStop[name] {
		return say("Pick another name — '" + name + "' is one of my own words.")
	}
	if host == "" {
		return say("Select him first — or say '" + name + " means <hostname>'.")
	}
	s.memoryMu.Lock()
	defer func() { saveMemoryFile(s.memory); s.memoryMu.Unlock() }()
	msg, ok := memBindName(s.memory, name, host, func(h string) bool {
		return s.findAgentByHostname(h) != nil
	})
	_ = ok
	return say(msg)
}

func (s *Server) memoryRepoint(name, href string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	name = strings.ToLower(strings.TrimSpace(name))
	if voiceNameStop[name] {
		return say("Pick another name — '" + name + "' is one of my own words.")
	}
	host, ok := s.resolveHostRef(href)
	if !ok {
		return say("Don't see '" + href + "' — hostname of a box I know?")
	}
	s.memoryMu.Lock()
	defer func() { saveMemoryFile(s.memory); s.memoryMu.Unlock() }()
	msg, _ := memBindName(s.memory, name, host, func(h string) bool {
		return s.findAgentByHostname(h) != nil
	})
	return say(msg)
}

func (s *Server) memoryAddFact(fact, scope, host string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	fact = strings.TrimSpace(fact)
	if fact == "" {
		return say("Remember what, exactly?")
	}
	h := host
	disp := host
	if scope != "" {
		rh, ok := s.memoryScopeHost(scope)
		if !ok {
			return say("I don't know '" + scope + "' — about whom?")
		}
		h, disp = rh, scope
	}
	if h == "" {
		return say("About whom? Select him or name him.")
	}
	if len(fact) > 200 {
		fact = fact[:200]
	}
	s.memoryMu.Lock()
	defer func() { saveMemoryFile(s.memory); s.memoryMu.Unlock() }()
	am := s.memGet(h)
	for _, f := range am.Facts {
		if strings.EqualFold(f, fact) {
			return say("Already got that one for " + disp + ".")
		}
	}
	if len(am.Facts) >= 50 {
		return say(disp + "'s list is full (50) — forget something first.")
	}
	am.Facts = append(am.Facts, fact)
	if disp == "" {
		disp = h
	}
	return say(fmt.Sprintf("Noted for %s.", disp))
}

func (s *Server) memoryRecall(scope, host string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	h, disp := host, host
	if scope != "" {
		rh, ok := s.memoryScopeHost(scope)
		if !ok {
			return say("I don't know '" + scope + "'.")
		}
		h, disp = rh, scope
	}
	if h == "" {
		return say("About whom? Select him or name him.")
	}
	s.memoryMu.Lock()
	am, _ := s.memory.Agents[h]
	var facts []string
	if am != nil {
		facts = append([]string(nil), am.Facts...)
	}
	if disp == "" {
		if am != nil && am.Name != "" {
			disp = am.Name
		} else {
			disp = h
		}
	}
	s.memoryMu.Unlock()
	if len(facts) == 0 {
		return say("Nothing on " + disp + " yet.")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", disp)
	for i, f := range facts {
		fmt.Fprintf(&b, "%d. %s\n", i+1, f)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	s.voiceMu.Lock()
	s.voice.recall = &voiceResult{lines: lines[1:], host: h, at: time.Now()}
	s.voiceMu.Unlock()
	return say(b.String())
}

func (s *Server) memoryWhoIs(name string) (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	name = strings.ToLower(strings.TrimSpace(name))
	s.memoryMu.Lock()
	host, ok := s.memory.Names[name]
	nfacts := 0
	if am, ok2 := s.memory.Agents[host]; ok2 {
		nfacts = len(am.Facts)
	}
	s.memoryMu.Unlock()
	if !ok {
		return say("Don't know " + name + " yet — select him and say 'his name is " + name + "'.")
	}
	online := s.findAgentByHostname(host) != nil
	st := "offline"
	if online {
		st = "online"
	}
	return say(fmt.Sprintf("%s is %s (%d fact(s), %s).", name, host, nfacts, st))
}

func (s *Server) memoryRepeat() (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	s.voiceMu.Lock()
	last := s.voice.last
	fresh := s.voiceFresh(last)
	s.voiceMu.Unlock()
	if !fresh {
		return say("Nothing cached — run something first, then 'again'.")
	}
	tac := s.findAgentByHostname(last.host)
	if tac == nil {
		return say(last.host + " is offline now.")
	}
	return true, tac, last.run, ""
}

func (s *Server) memoryReplay() (bool, *AgentConn, string, string) {
	say := func(t string) (bool, *AgentConn, string, string) { return true, nil, "", "🎙 " + t }
	s.voiceMu.Lock()
	last := s.voice.last
	fresh := s.voiceFresh(last)
	s.voiceMu.Unlock()
	if !fresh || len(last.lines) == 0 {
		return say("Nothing cached — run something first.")
	}
	return say("Last (" + last.run + "): " + strings.Join(last.lines, " · "))
}

func (s *Server) memorySummary() string {
	s.memoryMu.Lock()
	defer s.memoryMu.Unlock()
	var names []string
	for n, h := range s.memory.Names {
		names = append(names, n+"="+h)
	}
	sort.Strings(names)
	nf := 0
	for _, am := range s.memory.Agents {
		nf += len(am.Facts)
	}
	var prefs []string
	for k, v := range s.memory.Prefs {
		prefs = append(prefs, k+"="+v)
	}
	sort.Strings(prefs)
	return fmt.Sprintf("memory: %d host(s), %d fact(s), names [%s], prefs [%s]",
		len(s.memory.Agents), nf, strings.Join(names, ", "), strings.Join(prefs, ", "))
}

// memoryScopeHost resolves a scope word (name or hostname) to a hostname.
func (s *Server) memoryScopeHost(scope string) (string, bool) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		return "", false
	}
	s.memoryMu.Lock()
	defer s.memoryMu.Unlock()
	if h, ok := s.memory.Names[scope]; ok {
		return h, true
	}
	for h := range s.memory.Agents {
		if strings.EqualFold(h, scope) {
			return h, true
		}
	}
	return "", false
}

// resolveHostRef resolves free text to a known hostname (connected agents
// first, then any remembered hostname, else not found).
func (s *Server) resolveHostRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}
	if ac := s.findAgentByHostname(ref); ac != nil {
		return ac.hostname, true
	}
	if ac := s.findAgentFuzzy(ref); ac != nil {
		return ac.hostname, true
	}
	s.memoryMu.Lock()
	defer s.memoryMu.Unlock()
	for h := range s.memory.Agents {
		if strings.EqualFold(h, ref) {
			return h, true
		}
	}
	return "", false
}

// resolvePrefHost resolves a defaultAgent preference value (name or host).
func (s *Server) resolvePrefHost(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	if h, ok := s.memoryScopeHost(strings.ToLower(v)); ok {
		return h, true
	}
	return s.resolveHostRef(v)
}

// findAgentFuzzy matches an agent by id/hostname, exact then contains
// (case-insensitive), for operator-typed references.
func (s *Server) findAgentFuzzy(ref string) *AgentConn {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if ref == "" {
		return nil
	}
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()
	for _, ac := range s.agents {
		if strings.ToLower(ac.id) == ref || strings.ToLower(ac.hostname) == ref {
			return ac
		}
	}
	for _, ac := range s.agents {
		if strings.Contains(strings.ToLower(ac.hostname), ref) || strings.Contains(strings.ToLower(ac.id), ref) {
			return ac
		}
	}
	return nil
}

// resolveDefaultAgent honors the defaultAgent pref when no agent is
// selected (voice/memory commands only — never general routing).
func (s *Server) resolveDefaultAgent() *AgentConn {
	s.memoryMu.Lock()
	want := strings.TrimSpace(s.memory.Prefs["defaultAgent"])
	s.memoryMu.Unlock()
	if want == "" {
		return nil
	}
	if h, ok := s.memoryScopeHost(strings.ToLower(want)); ok {
		if ac := s.findAgentByHostname(h); ac != nil {
			return ac
		}
	}
	return s.findAgentFuzzy(want)
}

// voiceTarget returns ac, or the default agent when none is selected and
// the text is a voice/memory pseudo-command. Non-voice traffic is never
// rerouted.
func (s *Server) voiceTarget(ac *AgentConn, cmd string) *AgentConn {
	if ac != nil {
		return ac
	}
	if !isVoiceCmd(cmd) {
		return nil
	}
	return s.resolveDefaultAgent()
}

// parseOrdinalRef matches "open #2" / "open the second one" / "#2" / "7".
// Bare digits only resolve when a fresh listing exists (checked by the
// caller), so stray numbers never fire blindly.
func parseOrdinalRef(s string) (int, bool) {
	t := strings.TrimSpace(s)
	t = strings.TrimSpace(strings.TrimPrefix(t, "open "))
	t = strings.TrimSpace(strings.TrimPrefix(t, "the "))
	t = strings.TrimSpace(strings.TrimSuffix(t, " one"))
	t = strings.TrimSpace(strings.TrimPrefix(t, "number "))
	t = strings.TrimSpace(strings.TrimPrefix(t, "#"))
	if t == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(t); err == nil && n > 0 && n < 1000 {
		return n, true
	}
	if len(t) > 2 {
		if n, err := strconv.Atoi(t[:len(t)-2]); err == nil && n > 0 && n < 1000 {
			switch t[len(t)-2:] {
			case "st", "nd", "rd", "th":
				return n, true
			}
		}
	}
	if n, ok := forgetOrdinals[t]; ok {
		return n, true
	}
	return 0, false
}

// historyRowURL extracts the URL tail ("... | https://...") of a history row.
func historyRowURL(line string) string {
	i := strings.LastIndex(line, "|")
	if i < 0 {
		return ""
	}
	u := strings.TrimSpace(line[i+1:])
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	return ""
}

// ordinalOpen resolves an ordinal against the freshest listable voice
// result. Profile lists re-pull with #N; history rows open the Nth URL —
// both on the originating box. Anything else (or nothing fresh) declines
// so P1 intents still get their turn.
func (s *Server) ordinalOpen(n int) (tac *AgentConn, run, reply string, matched bool) {
	s.voiceMu.Lock()
	last := s.voice.last
	fresh := s.voiceFresh(last)
	s.voiceMu.Unlock()
	if !fresh || len(last.lines) == 0 {
		return nil, "", "", false
	}
	tac = s.findAgentByHostname(last.host)
	if tac == nil {
		return nil, "", "🎙 " + last.host + " is offline now.", true
	}
	lines := last.lines
	if strings.HasPrefix(lines[0], "profiles:") {
		if n < 1 || n > len(lines)-1 {
			return nil, "", fmt.Sprintf("🎙 Only %d profiles listed.", len(lines)-1), true
		}
		return tac, fmt.Sprintf("get-chrome-history 20 #%d", n), "", true
	}
	var urls []string
	for _, ln := range lines {
		if u := historyRowURL(ln); u != "" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return nil, "", "", false
	}
	if n < 1 || n > len(urls) {
		return nil, "", fmt.Sprintf("🎙 Only %d rows cached.", len(urls)), true
	}
	return tac, "open-url chrome " + urls[n-1], "", true
}

// retargetByName scans for a registered name token (or possessive) and
// returns that agent. Unknown/offline names yield a clarify note with nil
// agent; no match yields nil, "" (caller proceeds unchanged). Pronoun-like
// names can never register (bind-time stoplist), so plain tokens are safe.
func (s *Server) retargetByName(snorm string, ac *AgentConn) (*AgentConn, string) {
	snorm = normVoice(snorm)
	s.memoryMu.Lock()
	var names []string
	hosts := map[string]string{}
	for n, h := range s.memory.Names {
		names = append(names, n)
		hosts[n] = h
	}
	s.memoryMu.Unlock()
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	padded := " " + snorm + " "
	for _, n := range names {
		if strings.Contains(padded, " "+n+" ") || strings.Contains(padded, " "+n+"'s ") {
			tac := s.findAgentByHostname(hosts[n])
			if tac == nil {
				return nil, n + " is offline (last seen on " + hosts[n] + ")"
			}
			return tac, ""
		}
	}
	return nil, ""
}

// --- pure memory grammar (unit-tested, no server) ---

// cutPrefixWord strips a leading command word ("forget", "recall").
func cutPrefixWord(s, w string) (string, bool) {
	if s == w {
		return "", true
	}
	if strings.HasPrefix(s, w+" ") {
		return strings.TrimSpace(s[len(w)+1:]), true
	}
	return "", false
}

var forgetOrdinals = map[string]int{
	"first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5,
	"sixth": 6, "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10,
	"1st": 1, "2nd": 2, "3rd": 3,
}

// parseForgetOrdinal matches "forget 3" / "forget number 3" / "forget the third".
func parseForgetOrdinal(s string) (int, bool) {
	rest, ok := cutPrefixWord(s, "forget")
	if !ok {
		return 0, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rest, "number"), "#"))
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "the "))
	if fields := strings.Fields(rest); len(fields) == 1 {
		var n int
		if _, err := fmt.Sscanf(fields[0], "%d", &n); err == nil && n > 0 {
			return n, true
		}
		if n, ok := forgetOrdinals[strings.ToLower(fields[0])]; ok {
			return n, true
		}
	}
	return 0, false
}

// parsePrefSet matches "my <k> is <v>" / "my <k>=<v>" and the direct
// operator forms "remember [that] <head>..." for known heads (default
// agent, reply aloud, call me...), so "remember call me boss" works.
func parsePrefSet(s string) (k, v string, ok bool) {
	rest := s
	if r, ok2 := cutPrefixWord(s, "remember"); ok2 {
		rest = strings.TrimSpace(strings.TrimPrefix(r, "that "))
	}
	if strings.HasPrefix(rest, "my ") {
		body := strings.TrimSpace(rest[len("my "):])
		if i := strings.Index(body, "="); i >= 0 {
			return strings.TrimSpace(body[:i]), strings.TrimSpace(body[i+1:]), true
		}
		if i := strings.Index(body, " is "); i >= 0 {
			return strings.TrimSpace(body[:i]), strings.TrimSpace(body[i+4:]), true
		}
		return "", "", false
	}
	for _, head := range []string{"default agent", "reply aloud", "read aloud", "call me", "speak", "talk"} {
		if rest == head || strings.HasPrefix(rest, head+" ") || strings.HasPrefix(rest, head+"=") {
			v := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rest[len(head):], " "), "="))
			v = strings.TrimSpace(strings.TrimPrefix(v, "is "))
			v = strings.TrimSpace(strings.TrimPrefix(v, " "))
			return head, v, true
		}
	}
	return "", "", false
}

// parseBindName matches "his name is X" / "call him X" / "<n>'s name is X".
func parseBindName(s string) (string, bool) {
	if rest, ok := cutPrefixWord(s, "call him"); ok && rest != "" {
		return rest, true
	}
	if strings.HasPrefix(s, "his name is ") {
		if rest := strings.TrimSpace(s[len("his name is "):]); rest != "" {
			return rest, true
		}
	}
	if i := strings.Index(s, "'s name is "); i > 0 {
		if rest := strings.TrimSpace(s[i+len("'s name is "):]); rest != "" {
			return rest, true
		}
	}
	if rest, ok := cutPrefixWord(s, "remember"); ok {
		return parseBindName(rest)
	}
	return "", false
}

// parseMeans matches "<name> means <hostref>" (explicit re-point).
func parseMeans(s string) (name, href string, ok bool) {
	i := strings.Index(s, " means ")
	if i <= 0 {
		return "", "", false
	}
	name, href = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+len(" means "):])
	if name == "" || href == "" || len(strings.Fields(name)) > 3 {
		return "", "", false
	}
	return name, href, true
}

// parseRememberFact matches "remember [that] <fact> [about <scope>]".
func parseRememberFact(s string) (fact, scope string, ok bool) {
	rest, ok := cutPrefixWord(s, "remember")
	if !ok || rest == "" {
		return "", "", false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "that "))
	fact, scope = splitAbout(rest)
	return strings.TrimSpace(fact), strings.TrimSpace(scope), strings.TrimSpace(fact) != ""
}

// parseRecall matches recall verbs with optional scope.
func parseRecall(s string) (scope string, ok bool) {
	verbs := []string{"what do you remember", "recall", "list facts", "my notes", "show facts"}
	matched := false
	rest := s
	for _, v := range verbs {
		if r, ok2 := cutPrefixWord(s, v); ok2 {
			matched, rest = true, r
			break
		}
	}
	if !matched {
		return "", false
	}
	if scope, ok := cutAbout(rest); ok {
		return scope, true
	}
	if ab, ok := cutPrefixWord(rest, "about"); ok {
		return ab, true
	}
	return strings.TrimSpace(rest), true
}

// parseWhoIs matches "who is X" / "who's X".
func parseWhoIs(s string) (string, bool) {
	if rest, ok := cutPrefixWord(s, "who is"); ok && rest != "" {
		return rest, true
	}
	if strings.HasPrefix(s, "who's ") {
		if rest := strings.TrimSpace(s[len("who's "):]); rest != "" {
			return rest, true
		}
	}
	return "", false
}

// cutAbout splits trailing "about <scope>" (last occurrence wins).
func cutAbout(s string) (string, bool) {
	if i := strings.LastIndex(s, " about "); i >= 0 {
		if scope := strings.TrimSpace(s[i+len(" about "):]); scope != "" {
			return scope, true
		}
	}
	return "", false
}

// splitAbout splits "<main> about <scope>" (last " about " wins).
func splitAbout(s string) (main, scope string) {
	if i := strings.LastIndex(s, " about "); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+len(" about "):])
	}
	return strings.TrimSpace(s), ""
}

// stripFillers drops leading determiners so "his wifi password" matches a
// stored "wifi password is hunter2" by substring.
func stripFillers(frag string) string {
	for {
		changed := false
		for _, w := range []string{"his ", "my ", "the ", "that ", "this ", "a ", "an "} {
			if strings.HasPrefix(frag, w) {
				frag = strings.TrimSpace(frag[len(w):])
				changed = true
				break
			}
		}
		if !changed {
			return frag
		}
	}
}
