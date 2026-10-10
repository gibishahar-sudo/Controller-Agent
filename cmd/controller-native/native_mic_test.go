//go:build windows

package main

import (
	"strings"
	"testing"
)

// The recognizer snippet must load the constrained Jarvis grammar AND
// dictation, and gate on confidence (v1.47.1: unconstrained dictation
// returned word salad like "You're a modem is").
func TestBuildSpeechPS(t *testing.T) {
	if speechMinConfidence < 0.3 || speechMinConfidence > 0.8 {
		t.Fatalf("threshold implausible: %v", speechMinConfidence)
	}
	if len(jarvisGrammarPhrases) < 20 {
		t.Fatalf("vocabulary too small: %d", len(jarvisGrammarPhrases))
	}
	seen := map[string]bool{}
	for _, p := range jarvisGrammarPhrases {
		if seen[p] {
			t.Fatalf("dup phrase %q", p)
		}
		seen[p] = true
	}
	got := buildSpeechPS(jarvisGrammarPhrases, speechMinConfidence)
	for _, need := range []string{
		"GrammarBuilder", "DictationGrammar", "InitialSilenceTimeout",
		"EndSilenceTimeout", "Recognize()", ".Confidence",
		"what tabs does he have", "only searches", "memory status",
	} {
		if !strings.Contains(got, need) {
			t.Fatalf("snippet missing %q", need)
		}
	}
}
