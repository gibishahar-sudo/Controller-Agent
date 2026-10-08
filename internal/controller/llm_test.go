package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// llmPrompt is the proven P0r phrasing prompt (short, grounded).
func TestLLMPromptShape(t *testing.T) {
	sys, user := llmPrompt("Tabs open: YouTube, Gmail", "boss")
	if !strings.Contains(user, "Tabs open") || !strings.Contains(user, "boss") {
		t.Fatalf("prompt dropped context: %q / %q", sys, user)
	}
	if sys == "" {
		t.Fatal("empty system prompt")
	}
}

func TestLLMCompleteOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"  \"Three tabs.\"  "}}]}`)
	}))
	defer srv.Close()
	got, err := llmPost(srv.URL+"/v1/chat/completions", "sys", "user", 0.2, 40, 5*time.Second)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got != `  "Three tabs."  ` {
		t.Fatalf("transport must not mutate content: %q", got)
	}
}

func TestLLMCompleteTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	if _, err := llmPost(srv.URL+"/v1/chat/completions", "s", "u", 0, 10, 100*time.Millisecond); err == nil {
		t.Fatal("slow model must time out")
	}
}

func TestLLMCompleteBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	if _, err := llmPost(srv.URL+"/v1/chat/completions", "s", "u", 0, 10, 5*time.Second); err == nil {
		t.Fatal("http 500 must error")
	}
}

func TestLLMCleanLine(t *testing.T) {
	for in, want := range map[string]string{
		`  "Three tabs."  `: "Three tabs.",
		`'Hi boss.'`:              "Hi boss.",
		"  plain  ":               "plain",
	} {
		if got := llmCleanLine(in); got != want {
			t.Fatalf("clean %q = %q want %q", in, got, want)
		}
	}
	if llmCleanLine("") != "" {
		t.Fatal("empty must stay empty")
	}
}

func TestTryLLMCmdShapes(t *testing.T) {
	s := memTestServer()
	s.llm = newLLMState()
	for _, cmd := range []string{"llm-status", "llm-stop", "llm-pull", "llm-say hi", "llm-warm", "LLM-STATUS", "  llm-status  "} {
		h, rep := s.tryLLMCmd(cmd)
		if !h || rep == "" {
			t.Fatalf("%q: handled=%v rep=%q", cmd, h, rep)
		}
		if !strings.HasPrefix(rep, "🗣 ") {
			t.Fatalf("%q: missing mic prefix: %q", cmd, rep)
		}
	}
	for _, cmd := range []string{"get-processes", "voice-cmd hi", "llama", "llm", "llm-sayhi"} {
		if h, _ := s.tryLLMCmd(cmd); h {
			t.Fatalf("%q must not route to llm", cmd)
		}
	}
}

func TestPhraseCache(t *testing.T) {
	st := newLLMState()
	if _, ok := st.phraseGet("k"); ok {
		t.Fatal("empty cache must miss")
	}
	st.phrasePut("a", "Aye.")
	st.phrasePut("b", "Aye2.")
	if got, ok := st.phraseGet("a"); !ok || got != "Aye." {
		t.Fatalf("get a: %q %v", got, ok)
	}
	for i := 0; i < llmCacheCap+10; i++ {
		st.phrasePut(strings.Repeat("x", i+3), "v")
	}
	if len(st.phraseCache) > llmCacheCap {
		t.Fatalf("cache uncapped: %d", len(st.phraseCache))
	}
	if _, ok := st.phraseGet("a"); ok {
		t.Fatal("FIFO must evict the oldest first")
	}
	if k1, k2 := phraseKey("t", "boss"), phraseKey("t", "sir"); k1 == k2 {
		t.Fatal("callMe must scope the key")
	}
}

func TestIdleKillDur(t *testing.T) {
	st := newLLMState()
	if got := st.idleKillDur(); got != llmIdleKill {
		t.Fatalf("default: %v", got)
	}
	st.mu.Lock()
	st.warm = true
	st.mu.Unlock()
	if got := st.idleKillDur(); got != llmWarmIdle {
		t.Fatalf("warm: %v", got)
	}
}

func TestLLMWarmPref(t *testing.T) {
	s := memTestServer()
	s.llm = newLLMState()
	h, rep := s.tryLLMCmd("llm-warm")
	if !h || !strings.Contains(rep, "standby off") {
		t.Fatalf("bare warm reports: %v %q", h, rep)
	}
	h, rep = s.tryLLMCmd("llm-warm on")
	if !h || !strings.Contains(rep, "llm-pull first") {
		t.Fatalf("warm on without files: %v %q", h, rep)
	}
	if s.memory.Prefs["llmWarm"] != "1" {
		t.Fatal("warm pref must persist")
	}
	if !s.llm.warm {
		t.Fatal("runtime flag must follow the pref")
	}
	h, rep = s.tryLLMCmd("llm-warm off")
	if !h || !strings.Contains(rep, "standby off") {
		t.Fatalf("warm off: %v %q", h, rep)
	}
	if _, ok := s.memory.Prefs["llmWarm"]; ok {
		t.Fatal("warm off must clear the pref")
	}
}

func TestLLMPromptWordCap(t *testing.T) {
	sys, _ := llmPrompt("ctx", "")
	if !strings.Contains(sys, "20 words") {
		t.Fatalf("prompt must cap length: %q", sys)
	}
}
