//go:build windows

package main

import "testing"

func TestMpMissing(t *testing.T) {
	have := []string{`C:\Program Files\RMM`, `C:\X\A.EXE`}
	cases := []struct {
		want []string
		miss []string
	}{
		{[]string{`C:\Program Files\RMM`}, nil},
		{[]string{`c:\program files\rmm\`}, nil}, // case + slash tolerant
		{[]string{`C:\Program Files\RMM`, `C:\Y\B.EXE`}, []string{`C:\Y\B.EXE`}},
		{nil, nil},
	}
	for _, c := range cases {
		got := mpMissing(have, c.want)
		if len(got) != len(c.miss) {
			t.Fatalf("mpMissing(%q) = %q want %q", c.want, got, c.miss)
		}
		for i := range got {
			if got[i] != c.miss[i] {
				t.Fatalf("mpMissing(%q) = %q want %q", c.want, got, c.miss)
			}
		}
	}
}
