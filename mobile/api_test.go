package mobile

import (
	"strings"
	"testing"
)

func TestRingLog(t *testing.T) {
	r := newRingLog(3)
	if _, err := r.Write([]byte("a\nb\n")); err != nil {
		t.Fatal(err)
	}
	got := r.tail(10)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("tail = %q", got)
	}
	r.Write([]byte("c\nd\ne\n"))
	got = r.tail(10)
	if len(got) != 3 || got[0] != "c" || got[2] != "e" {
		t.Fatalf("evict tail = %q", got)
	}
	if got := r.tail(0); len(got) != 0 {
		t.Fatalf("tail(0) = %q", got)
	}
}

func TestStrField(t *testing.T) {
	m := map[string]interface{}{"hostname": "PC", "n": 7}
	if strField(m, "hostname") != "PC" {
		t.Fatal("string field")
	}
	if strField(m, "n") != "7" {
		t.Fatal("non-string coerced")
	}
	if strField(m, "missing") != "" {
		t.Fatal("missing must be empty")
	}
}

func TestStartRequiresSecrets(t *testing.T) {
	if got := Start(t.TempDir(), "tok", "", "c", "k"); got == "" || !strings.Contains(got, "UI password") {
		t.Fatalf("empty password must fail, got %q", got)
	}
	// Empty identity args fall back to pre-placed files; bare dir fails loud.
	if got := Start(t.TempDir(), "", "pw", "", ""); got == "" || !strings.Contains(got, "agent_token.txt") {
		t.Fatalf("missing pre-placed identity must fail, got %q", got)
	}
	if got := Stop(); got != "" {
		t.Fatalf("stop-when-idle must be empty, got %q", got)
	}
}
