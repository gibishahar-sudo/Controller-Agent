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
		"for($i=0;$i -lt 3",
		"download incomplete",
		"--silent",
		"not admin - approve the UAC prompt",
		"Start-Process powershell -Verb RunAs",
		"elevated installer exit=",
		"UAC declined or unavailable",
		"e='+$c.ExitCode",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("cmd missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"`) {
		t.Fatal("double quote leak breaks the outer call shape")
	}
	if !strings.Contains(got, "whoami /groups") {
		t.Fatal("role check must use whoami (.NET shorthand fails on PS 5.1)")
	}
	if strings.Contains(got, "Start-Process $o '--silent' -Verb RunAs") {
		t.Fatal("payload must never be RunAs'd directly (UAC names PowerShell now)")
	}
}

func TestBuildInstallCMDMode(t *testing.T) {
	iwr := buildInstallCMDMode("TOK", "123", 18616816, "iwr")
	if !strings.Contains(iwr, "iwr -Headers @{Authorization=") {
		t.Fatalf("iwr mode lost its fetcher:\n%s", iwr)
	}
	if strings.Contains(iwr, "curl.exe") {
		t.Fatal("iwr mode must not mention curl")
	}
	curl := buildInstallCMDMode("TOK", "123", 18616816, "curl")
	for _, want := range []string{
		"curl.exe", "-C -", "--retry", "--retry-all-errors", "--max-time",
		"18616816", "releases/assets/123",
	} {
		if !strings.Contains(curl, want) {
			t.Fatalf("curl mode missing %q:\n%s", want, curl)
		}
	}
	if strings.Contains(curl, "$h[") {
		t.Fatal("curl mode must inline headers (no $h array)")
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
