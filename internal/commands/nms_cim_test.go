package commands

import (
	"strings"
	"testing"
)

// Both halves of remote execution must survive together: the DCOM transport
// option AND the -CimSession/-SessionOption wiring. They were built months
// apart by different sessions; deleting either half silently breaks remote
// execution while local runs keep reporting success.
func TestCimDcomWiring(t *testing.T) {
	scripts := map[string]string{
		"stats": cimStatsScript("h"),
		"cred":  cimStatsCredScript("h"),
		"create": cimCreateScript("h",
			`C:\Windows\Temp\Agent-Setup.exe --silent`),
	}
	for name, s := range scripts {
		if !strings.Contains(s, "New-CimSessionOption -Protocol Dcom") {
			t.Fatalf("%s: DCOM option missing", name)
		}
		if !strings.Contains(s, "-SessionOption $opt") {
			t.Fatalf("%s: session not wired to DCOM option", name)
		}
		if c := countStr(s, "New-CimSession -ComputerName"); c != 1 {
			t.Fatalf("%s: want exactly 1 session construction, got %d", name, c)
		}
	}
	// The local-execution regression: every invoke MUST name the session.
	create := scripts["create"]
	if !strings.Contains(create, "Invoke-CimMethod -CimSession $s") {
		t.Fatal("create must invoke on -CimSession $s (local-execution regression)")
	}
	for _, s := range []string{scripts["stats"], scripts["cred"]} {
		if !strings.Contains(s, "Get-CimInstance -CimSession $s") {
			t.Fatal("stats queries must run on -CimSession $s")
		}
	}
	// Hostname escaping survives the prelude splice.
	if s := cimCreateScript("o'brien", "x"); !strings.Contains(s, "o''brien") {
		t.Fatalf("host escaping broken: %q", s)
	}
}

func countStr(s, sub string) int {
	n := 0
	for {
		i := strings.Index(s, sub)
		if i < 0 {
			return n
		}
		n++
		s = s[i+len(sub):]
	}
}
