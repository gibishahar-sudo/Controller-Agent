package controller

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMapSandboxPath(t *testing.T) {
	root := filepath.Join("TMP", "RMM", "files")
	join := func(elems ...string) string {
		return filepath.Join(append([]string{root}, elems...)...)
	}
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{`C:\`, root, false},
		{`C:\Users\Shahar\x.mp4`, join("Users", "Shahar", "x.mp4"), false},
		{`c:\users\a b\c.txt`, join("users", "a b", "c.txt"), false},
		{`D:\songs\y.mp3`, join("songs", "y.mp3"), false},
		{`C:/forward/slashes.txt`, join("forward", "slashes.txt"), false},
		{`/already/native.txt`, `/already/native.txt`, false},
		{`relative.txt`, `relative.txt`, false},
		// Clean clamps ".." at the jail wall: traversal collapses
		// inward, never outward. The loop below asserts containment.
		{`..\..\Windows\evil.exe`, join("Windows", "evil.exe"), false},
		{`C:\..\..\evil.exe`, join("evil.exe"), false},
		{``, "", true},
	}
	for _, c := range cases {
		got, err := mapSandboxPath(root, c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("mapSandboxPath(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("mapSandboxPath(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("mapSandboxPath(%q) = %q want %q", c.in, got, c.want)
			continue
		}
		// Mapped (backslash/drive) outputs must stay inside the jail;
		// native passthrough is operator-trusted by design.
		mapped := strings.Contains(c.in, "\\") || (len(c.in) >= 2 && c.in[1] == ':')
		if mapped && got != root && !strings.HasPrefix(got, root+string(filepath.Separator)) && got != filepath.Clean(root) {
			t.Errorf("mapSandboxPath(%q) = %q escapes root %q", c.in, got, root)
		}
	}
}
