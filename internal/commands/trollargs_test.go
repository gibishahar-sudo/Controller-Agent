package commands

import (
	"strings"
	"testing"
)

// splitTrollArgs must survive paths with spaces (v1.47.1: naive Fields
// splitting turned "C:\... FunnySongs\word_spam.mp4 100" into a usage
// error). Trailing noloop, then trailing digits = seconds, rest = path.
func TestSplitTrollArgs(t *testing.T) {
	def := defaultTrollSeconds
	cases := []struct {
		in         string
		src        string
		secs       int
		loop       bool
		ok         bool
	}{
		{`C:\v\clip.mp4`, `C:\v\clip.mp4`, def, true, true},
		{`C:\Funny Songs\word_spam.mp4 100`, `C:\Funny Songs\word_spam.mp4`, 100, true, true},
		{`"C:\Funny Songs\word_spam.mp4" 100`, `C:\Funny Songs\word_spam.mp4`, 100, true, true},
		{`https://x/y.mp4 noloop`, `https://x/y.mp4`, def, false, true},
		{`C:\v\clip.mp4 45 noloop`, `C:\v\clip.mp4`, 45, false, true},
		{`C:\v\clip.mp4 99999`, `C:\v\clip.mp4`, maxTrollSeconds, true, true},
		{`C:\v\clip.mp4 0`, ``, 0, true, false},
		{``, ``, 0, true, false},
		{`noloop`, ``, 0, true, false},
		{`C:\vids\2024.mp4`, `C:\vids\2024.mp4`, def, true, true},
	}
	for _, c := range cases {
		src, secs, loop, ok := splitTrollArgs(c.in)
		if src != c.src || secs != c.secs || loop != c.loop || ok != c.ok {
			t.Fatalf("split %q = (%q,%d,%v,%v) want (%q,%d,%v,%v)",
				c.in, src, secs, loop, ok, c.src, c.secs, c.loop, c.ok)
		}
	}
	// playTroll with a spaced missing path must say "not found", never usage.
	if _, err := playTroll(`C:\no such dir\nope.mp4 10`); err == nil || strings.Contains(err.Error(), "usage:") {
		t.Fatalf("spaced missing path: %v", err)
	}
}
