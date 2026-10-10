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

func TestBuildInstallCMDMode(t *testing.T) {
	iwr := buildInstallCMDMode("TOK", "123", 18616816, "iwr")
	if !strings.Contains(iwr, "Invoke-WebRequest") && !strings.Contains(iwr, "iwr -Headers ($h+@{Accept=") {
		t.Fatalf("iwr mode lost its fetcher:\n%s", iwr)
	}
	if strings.Contains(iwr, "curl.exe") {
		t.Fatal("iwr mode must not mention curl")
	}
	curl := buildInstallCMDMode("TOK", "123", 18616816, "curl")
	for _, want := range []string{
		"curl.exe", "-C -", "--retry", "--retry-all-errors",
		"-H $h[0]", "-H $h[1]", "18616816", "releases/assets/123",
	} {
		if !strings.Contains(curl, want) {
			t.Fatalf("curl mode missing %q:\n%s", want, curl)
		}
	}
	if strings.Contains(curl, "($h+@{Accept=") {
		t.Fatal("curl mode must not use hashtable header merge")
	}
	for _, m := range []string{"iwr", "curl", "bogus"} {
		line, err := encodeCMD(buildInstallCMDMode("T", "1", 2, m))
		if err != nil {
			t.Fatalf("mode %q encode: %v", m, err)
		}
		if !strings.HasPrefix(line, "powershell -WindowStyle Hidden -EncodedCommand ") {
			t.Fatalf("mode %q prefix", m)
		}
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
