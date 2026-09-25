//go:build windows

package commands

import (
	"testing"
	"time"

	"rmm/internal/cmdlist"
)

func TestParseKeylogDur(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 60 * time.Second},
		{"90", 90 * time.Second},
		{"90s", 90 * time.Second},
		{"5m", 300 * time.Second},
		{"1", 5 * time.Second},       // clamped to minimum
		{"99999", 3600 * time.Second}, // clamped to maximum
		{"120m", 3600 * time.Second},  // clamped to maximum
	}
	for _, c := range cases {
		got, err := parseKeylogDur(c.in)
		if err != nil {
			t.Fatalf("parseKeylogDur(%q) error: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parseKeylogDur(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"abc", "0", "-5", "10ms", "s", "m"} {
		if _, err := parseKeylogDur(bad); err == nil {
			t.Fatalf("parseKeylogDur(%q) should error", bad)
		}
	}
}

// The keylog verb must stay listed or help/autocomplete hides a live command.
func TestKeylogInKnown(t *testing.T) {
	if _, ok := cmdlist.Known["keylog"]; !ok {
		t.Fatal("keylog missing from cmdlist.Known")
	}
}
