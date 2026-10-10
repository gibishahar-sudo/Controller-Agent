package main

import (
	"strings"
	"testing"
)

// The size gate is the whole point (v1.47.3: 8% truncated binary ran
// silent). Shape + retry + gate must all survive refactors.
func TestBuildInstallCMD(t *testing.T) {
	got := buildInstallCMD("TOK", "123", 18616816)
	for _, want := range []string{
		"Bearer TOK",
		"releases/assets/123",
		"18616816",
		"for($i=1;$i -le 3",
		"Test-Path",
		"download incomplete after 3 tries",
		"--silent",
		"e='+$c.ExitCode",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("cmd missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"`) {
		t.Fatal("double quote leak breaks the outer call shape")
	}
}

func TestEncodeCMD(t *testing.T) {
	line, err := encodeCMD(buildInstallCMD("T", "1", 2))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.HasPrefix(line, "powershell -WindowStyle Hidden -EncodedCommand ") {
		t.Fatalf("prefix: %q", line)
	}
	if _, err := encodeCMD(`say "hi"`); err == nil {
		t.Fatal("double quotes must be refused")
	}
}
