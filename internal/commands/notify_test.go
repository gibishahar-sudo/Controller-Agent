package commands

import (
	"strings"
	"testing"
)

func TestNotifyScriptMarkers(t *testing.T) {
	s := notifyScript("hello", 5000)
	for _, want := range []string{
		"RMM Controller",
		"TopMost = $true",
		"ShowDialog",
		"Add_Shown",
		"Activate",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("notify script missing marker %q", want)
		}
	}
	if !strings.Contains(s, "hello") {
		t.Fatal("notify script missing text")
	}
	// Quoting: hostile text must stay inside the double-quoted string —
	// quote doubled, dollar backticked (psDQString contract).
	q := notifyScript(`a"b$c`, 0)
	if !strings.Contains(q, `a""b`) || !strings.Contains(q, "`$c") {
		t.Fatalf("notify text quoting broken: %s", q)
	}
}

func TestSendNotificationUsage(t *testing.T) {
	for _, bad := range []string{"", "hello", "0 hi", "-5 hi", "999999999 hi", "10 "} {
		if _, err := sendNotification(bad); err == nil {
			t.Fatalf("sendNotification(%q) should error", bad)
		}
	}
}
