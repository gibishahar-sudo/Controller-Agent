package controller

import (
	"testing"
	"time"
)

func TestRetryGraceFor(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"play-troll C:\\v.mp4 60", 75 * time.Second},
		{"PLAY-TROLL x 10", 75 * time.Second},
		{"keylog 120", 150 * time.Second},
		{"keylog", 90 * time.Second},
		{"keylog 99999", 3630 * time.Second},
		{"troll-selftest", 45 * time.Second},
		{"send-notification 10 hi", 45 * time.Second},
		{"version", 10 * time.Second},
		{"", 10 * time.Second},
		{"run-command foo", 10 * time.Second},
	}
	for _, c := range cases {
		if got := retryGraceFor(c.in); got != c.want {
			t.Errorf("retryGraceFor(%q) = %v want %v", c.in, got, c.want)
		}
	}
}
