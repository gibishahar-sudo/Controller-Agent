//go:build windows

package commands

import "testing"

func TestParseKeyPressTokens(t *testing.T) {
	for _, tc := range []struct {
		in    string
		downs int // expected key-down events (modifiers + main)
	}{
		{"{ENTER}", 1},
		{"{TAB}", 1},
		{"{F5}", 1},
		{"{LEFT}", 1},
		{"{BACKSPACE}", 1},
		{"a", 1},
		{"5", 1},
		{"^s", 2},  // ctrl + s
		{"%x", 2},  // alt + x
		{"^+s", 3}, // ctrl + shift + s
	} {
		in, err := parseKeyPress(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		downs := 0
		for _, ev := range in {
			if ev.U[4]&keyeventfKeyup == 0 {
				downs++
			}
		}
		if downs != tc.downs {
			t.Fatalf("%q: %d downs, want %d (total events %d)", tc.in, downs, tc.downs, len(in))
		}
		if len(in)%2 != 0 {
			t.Fatalf("%q: odd event count %d (downs must pair with ups)", tc.in, len(in))
		}
	}
}

func TestParseKeyPressRejects(t *testing.T) {
	for _, bad := range []string{"", "{NOPE}", "ab", "{PRTSC}"} {
		if _, err := parseKeyPress(bad); err == nil {
			t.Fatalf("%q: expected error", bad)
		}
	}
}
