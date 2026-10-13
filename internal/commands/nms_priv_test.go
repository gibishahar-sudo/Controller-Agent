package commands

import (
	"strings"
	"testing"
)

const whoamiElevated = `"Group Name","Type","SID","Attributes"
"Mandatory Label\High Mandatory Level","Label","S-1-16-12288","Mandatory group, Enabled by default, Enabled"
"BUILTIN\Administrators","Alias","S-1-5-32-544","Mandatory group, Enabled by default, Enabled"
"Everyone","Well-known group","S-1-1-0","Mandatory group, Enabled by default, Enabled"`

const whoamiFiltered = `"Group Name","Type","SID","Attributes"
"Mandatory Label\Medium Mandatory Level","Label","S-1-16-8192","Mandatory group, Enabled by default, Enabled"
"BUILTIN\Administrators","Alias","S-1-5-32-544","Group used for deny only"`

const whoamiSystem = `"Group Name","Type","SID","Attributes"
"Mandatory Label\System Mandatory Level","Label","S-1-16-16384","Mandatory group, Enabled by default, Enabled"
"BUILTIN\Administrators","Alias","S-1-5-32-544","Mandatory group, Enabled by default, Enabled, Owner"`

// Integrity RIDs map to levels; garbage stays identifiable.
func TestIntegrityFromLabel(t *testing.T) {
	cases := map[string]string{
		"S-1-16-4096": "low", "S-1-16-8192": "medium",
		"S-1-16-12288": "high", "S-1-16-16384": "system",
		"S-1-16-9999": "unknown(S-1-16-9999)",
	}
	for sid, want := range cases {
		if got := integrityFromLabel(sid); got != want {
			t.Fatalf("%s = %q want %q", sid, got, want)
		}
	}
}

// whoami parsing: elevated admin, filtered (deny-only) admin, system.
func TestParseWhoamiGroups(t *testing.T) {
	elev, integ, admin := parseWhoamiGroups(whoamiElevated)
	if !elev || !admin || integ != "high" {
		t.Fatalf("elevated: %v %q %v", elev, integ, admin)
	}
	elev, integ, admin = parseWhoamiGroups(whoamiFiltered)
	if elev || admin || integ != "medium" {
		t.Fatalf("filtered admin must read unelevated non-admin medium: %v %q %v", elev, integ, admin)
	}
	elev, integ, admin = parseWhoamiGroups(whoamiSystem)
	if !elev || !admin || integ != "system" {
		t.Fatalf("system: %v %q %v", elev, integ, admin)
	}
	elev, integ, admin = parseWhoamiGroups("garbage\n")
	if elev || admin || integ != "unknown" {
		t.Fatalf("garbage must read zero: %v %q %v", elev, integ, admin)
	}
}

// Remote section names the credential source and, on denial, the
// workgroup fix (no secrets ever appear in it).
func TestRemotePrivSection(t *testing.T) {
	withNMSRoot(t, t.TempDir())
	out := remotePrivSection("192.0.2.99", false, true)
	for _, want := range []string{"credential source:", "LocalAccountTokenFilterPolicy", "Administrators"} {
		if !strings.Contains(out, want) {
			t.Fatalf("denial guidance missing %q:\n%s", want, out)
		}
	}
	out = remotePrivSection("192.0.2.99", true, false)
	if strings.Contains(out, "LocalAccountTokenFilterPolicy") {
		t.Fatalf("clean path must not lecture:\n%s", out)
	}
}

// nms-status carries the priv summary; reports carry the priv block.
func TestPrivSurfaced(t *testing.T) {
	dir := t.TempDir()
	withNMSRoot(t, dir)
	stubDiscoveryNil(t)
	freezeSweepCache(t)
	oldStart := guardStartAgent
	guardStartAgent = func() error { return nil }
	t.Cleanup(func() { guardStartAgent = oldStart })
	_ = SaveNMSConfig(NMSConfig{IntervalSec: 60, Subnets: nil, AutoClone: false})
	st, err := NMSHandle("nms-status", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st, "priv=") {
		t.Fatalf("status must carry priv:\n%s", st)
	}
	var got string
	if err := StepNMS(func(j string) { got = j }, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"priv":{`) || !strings.Contains(got, `"integrity":`) {
		t.Fatalf("report must carry priv block:\n%.300s", got)
	}
}
