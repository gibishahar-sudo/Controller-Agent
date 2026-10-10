//go:build windows

package commands

import (
	"strings"
	"testing"
)

func TestParseAgentLimits(t *testing.T) {
	cases := []struct {
		in      string
		cpu     int
		mem     int64
		prio    string
		wantErr string
	}{
		{"cpu=15 mem=512 prio=idle", 15, 512, "idle", ""},
		{"prio=below", 0, 0, "below", ""},
		{"cpu=0 mem=0", 0, 0, "", ""},
		{"cpu=100", 100, 0, "", ""},
		{"cpu=4", 0, 0, "", "starves"},
		{"cpu=101", 0, 0, "", "0-100"},
		{"cpu=x", 0, 0, "", "0-100"},
		{"mem=64", 0, 0, "", "128MB"},
		{"mem=-5", 0, 0, "", "MB >="},
		{"mem=256", 0, 256, "", ""},
		{"prio=turbo", 0, 0, "", "idle|below|normal"},
		{"bogus=1", 0, 0, "", "unknown key"},
		{"cpu", 0, 0, "", "key=value"},
		{"CPU=20 MEM=256 PRIO=IDLE", 20, 256, "idle", ""},
	}
	for _, c := range cases {
		got, err := ParseAgentLimits(c.in)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("ParseAgentLimits(%q) err=%v, want %q", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAgentLimits(%q) unexpected err: %v", c.in, err)
			continue
		}
		if got.CPU != c.cpu || got.MemMB != c.mem || got.Prio != c.prio {
			t.Errorf("ParseAgentLimits(%q) = %+v want cpu=%d mem=%d prio=%q",
				c.in, got, c.cpu, c.mem, c.prio)
		}
	}
}

func TestStealthDefaultLimits(t *testing.T) {
	d := StealthDefaultLimits()
	if d.CPU != 15 || d.MemMB != 512 || d.Prio != "idle" {
		t.Fatalf("stealth defaults = %+v", d)
	}
}

// QuietLimits is the barely-noticeable preset: legal minimums on every
// axis (v1.47.4 "limit-agent quiet").
func TestQuietLimits(t *testing.T) {
	q := QuietLimits()
	if q.CPU != 5 || q.MemMB != 256 || q.Prio != "idle" {
		t.Fatalf("quiet = %+v", q)
	}
	if _, err := ParseAgentLimits("cpu=5 mem=256 prio=idle"); err != nil {
		t.Fatalf("preset must pass the parser's own floors: %v", err)
	}
}

// ExpandLimitPreset rewrites only the bare preset, byte-identical else.
func TestExpandLimitPreset(t *testing.T) {
	if got := ExpandLimitPreset("quiet"); got != "cpu=5 mem=256 prio=idle" {
		t.Fatalf("quiet = %q", got)
	}
	if got := ExpandLimitPreset("  QUIET  "); got != "cpu=5 mem=256 prio=idle" {
		t.Fatalf("QUIET = %q", got)
	}
	for _, passthrough := range []string{"", "clear", "cpu=10", "cpu=5 mem=256 prio=idle", "quieter", "unquiet"} {
		if got := ExpandLimitPreset(passthrough); got != passthrough {
			t.Fatalf("passthrough %q mangled to %q", passthrough, got)
		}
	}
}

func TestLimitsReportSmoke(t *testing.T) {
	// Read-only syscalls only: must never error on a healthy box.
	rep, err := limitsReport()
	if err != nil {
		t.Fatalf("limitsReport: %v", err)
	}
	if !strings.Contains(rep, "limits:") || !strings.Contains(rep, "live:") {
		t.Fatalf("report missing sections: %q", rep)
	}
}
