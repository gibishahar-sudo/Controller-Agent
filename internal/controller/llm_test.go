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
	for _, cmd := range []string{"llm-status", "llm-stop", "llm-pull", "llm-say hi", "LLM-STATUS", "  llm-status  "} {
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
