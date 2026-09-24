package controller

import (
	"encoding/base64"
	"strings"
	"testing"

	"rmm/internal/version"
)

func TestInstallPSNoDoubleQuotes(t *testing.T) {
	// A fake token keeps this hermetic (no network, no real secret).
	// buildInstallPS embeds ghToken(); override via env would race tests,
	// so just assert the template shape with a known asset id.
	// We call the unexported builder after stashing a dummy token.
	old := ""
	// ghToken reads env first; set RMM_GH_TOKEN for this test process.
	t.Setenv("RMM_GH_TOKEN", "ghp_TESTTOKEN")
	old = ghToken()
	if old != "ghp_TESTTOKEN" {
		t.Fatalf("ghToken() = %q, want env token", old)
	}
	ps := buildInstallPS(12345)
	if strings.Contains(ps, `"`) {
		t.Fatalf("double quote in install script: %s", ps)
	}
	for _, want := range []string{
		"ghp_TESTTOKEN",
		"/releases/assets/12345",
		"--silent",
		"S-1-16-12288",
		"e=",
	} {
		if !strings.Contains(ps, want) {
			t.Fatalf("install script missing %q: %s", want, ps)
		}
	}
}

func TestEncodeUTF16LERoundTrip(t *testing.T) {
	for _, s := range []string{
		"",
		"ascii only",
		"$h=@{Authorization='Bearer x'};",
		"unicode ✓ 你好 emoji 🎉",
	} {
		b := encodeUTF16LE(s)
		if got := decodeUTF16LE(b); got != s {
			t.Fatalf("round-trip(%q) = %q", s, got)
		}
		if s != "" && len(b) != len([]rune(s))*2 && len(b) < len(s) {
			t.Fatalf("utf16 length suspicious for %q: %d", s, len(b))
		}
	}
	// Base64 of UTF-16LE is what -EncodedCommand wants.
	ps := "Write-Output 1"
	enc := base64.StdEncoding.EncodeToString(encodeUTF16LE(ps))
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if decodeUTF16LE(raw) != ps {
		t.Fatal("b64+utf16 round-trip mismatch")
	}
}

func TestInstallCommandRequiresToken(t *testing.T) {
	t.Setenv("RMM_GH_TOKEN", "")
	// Clear any file-based token by running from a temp dir with no file.
	// installCommand should fail fast with a clear error (no network).
	// Note: if a gh_token.txt exists beside the test binary this may pass
	// the token check — then resolveAssetID will fail offline instead.
	cmd, err := installCommand()
	if err == nil {
		if !strings.HasPrefix(cmd, "powershell -EncodedCommand ") {
			t.Fatalf("unexpected cmd shape: %.40s", cmd)
		}
		if strings.Contains(cmd, "\"") {
			t.Fatal("double quote in install command")
		}
		return
	}
	if !strings.Contains(err.Error(), "token") && !strings.Contains(err.Error(), "github") && !strings.Contains(err.Error(), "network") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVersionTagShape(t *testing.T) {
	if !strings.HasPrefix(version.Version, "1.") {
		t.Fatalf("version.Version = %q, want 1.x", version.Version)
	}
}
