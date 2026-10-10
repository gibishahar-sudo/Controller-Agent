//go:build windows

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// hideNativeMicWindow spawns the listener with no console flash.
func hideNativeMicWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

// jarvisGrammarPhrases is the constrained recognition vocabulary: when
// the operator says something close to these, the engine snaps to the
// phrase instead of dictating word salad. Dictation stays loaded for
// everything else. Keep in sync with parseVoiceCmd intents + help text.
var jarvisGrammarPhrases = []string{
	"what tabs does he have", "show me the tabs", "show tabs",
	"pull his history", "show me history", "pull his search history",
	"only searches", "just searches",
	"open youtube", "open google", "open gmail", "open github",
	"open netflix", "open spotify", "open a new tab", "open new tab",
	"what is he doing", "what are you doing", "show active window",
	"memory status", "remember", "forget", "who is", "call me",
	"help", "what can you do", "can you do",
	"yes", "no", "open one", "open two", "open three",
	"one", "two", "three", "first", "second", "third",
}

// speechMinConfidence floors transcripts (v1.47.1): below this the
// engine is guessing ("As", "The new hope") and honesty ("heard
// nothing — try again") beats sending salad to the parser. Real
// commands score 0.7+.
const speechMinConfidence = 0.55

// buildSpeechPS renders the recognizer snippet for phrases + threshold
// (pure seam: the text is untestable live, the vocabulary is not).
func buildSpeechPS(phrases []string, minConf float64) string {
	quoted := make([]string, 0, len(phrases))
	for _, p := range phrases {
		quoted = append(quoted, "'"+strings.ReplaceAll(p, "'", "''")+"'")
	}
	return `Add-Type -AssemblyName System.Speech;` +
		`$rec = New-Object System.Speech.Recognition.SpeechRecognitionEngine([System.Globalization.CultureInfo]::GetCultureInfo('en-US'));` +
		`$choices = New-Object System.Speech.Recognition.Choices(@(` + strings.Join(quoted, ",") + `));` +
		`$gb = New-Object System.Speech.Recognition.GrammarBuilder;` +
		`$gb.Append($choices);` +
		`$g = New-Object System.Speech.Recognition.Grammar($gb);` +
		`$g.Name = 'jarvis';` +
		`$rec.LoadGrammar($g);` +
		`$rec.LoadGrammar((New-Object System.Speech.Recognition.DictationGrammar));` +
		`$rec.InitialSilenceTimeout = [TimeSpan]::FromSeconds(8);` +
		`$rec.EndSilenceTimeout = [TimeSpan]::FromSeconds(1.5);` +
		`try { $rec.SetInputToDefaultAudioDevice(); } catch { exit 2 };` +
		`try { $r = $rec.Recognize(); } catch { exit 3 };` +
		`if ($r -ne $null -and $r.Confidence -ge ` + strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", minConf), "0"), ".") + `) { $r.Text }`
}

// windowsSpeechOnce runs one blocking Windows Speech Recognition pass
// (System.Speech, in-box since Vista — no downloads, no cloud) and returns
// the transcript, "" when nothing was heard (or heard unconfidently).
// The caller runs it off the UI thread with its own overall timeout; the
// recognition itself is bounded by initial/end silence timeouts so a
// quiet room always resolves.
func windowsSpeechOnce(timeout time.Duration) string {
	ps := buildSpeechPS(jarvisGrammarPhrases, speechMinConfidence)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	// No console window: the listener runs beside a GUI with no flash.
	hideNativeMicWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
