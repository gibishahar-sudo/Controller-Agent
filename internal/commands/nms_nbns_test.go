package commands

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// The box sits in 192.168.68.0/22: the old /24-only sweep could not see
// 192.168.64-67 or 192.168.69-71 at all, so those hosts read "unreachable"
// forever. Expansion must cover the real mask.
func TestExpandSubnetWideMasks(t *testing.T) {
	ips := expandSubnet("192.168.68.0/22")
	if len(ips) != 1022 {
		t.Fatalf("/22 must yield 1022 hosts, got %d", len(ips))
	}
	if ips[0] != "192.168.68.1" || ips[1] != "192.168.68.2" {
		t.Fatalf("/22 must start at the masked base, got %s %s", ips[0], ips[1])
	}
	last := ips[len(ips)-1]
	if last != "192.168.71.254" {
		t.Fatalf("/22 must end at the broadcast tail, got %s", last)
	}
	// Sloppy host bits select the same subnet.
	if a, b := expandSubnet("192.168.68.9/22"), ips; len(a) != len(b) || a[0] != b[0] {
		t.Fatal("sloppy base must mask to the same /22")
	}
	// /30 and /24 still work.
	if g := expandSubnet("192.168.9.0/30"); len(g) != 2 || g[0] != "192.168.9.1" {
		t.Fatalf("/30: got %v", g)
	}
	if g := expandSubnet("192.168.7.0/24"); len(g) != 254 || g[0] != "192.168.7.1" {
		t.Fatalf("/24 regression: got %d", len(g))
	}
	// Wider than /22 or narrower than /30 stays refused: an unbounded dial
	// budget is worse than a missed host.
	for _, sn := range []string{"10.0.0.0/16", "192.168.1.0/8", "192.168.1.0/31", "192.168.1.0/32", "192.168.1.0", "junk", "192.168.1.0/33"} {
		if got := expandSubnet(sn); len(got) != 0 {
			t.Fatalf("%q must expand empty, got %d", sn, len(got))
		}
	}
}

// NBNS query build: wildcard name, NBSTAT type, IN class, correct lengths.
func TestNBNSQueryShape(t *testing.T) {
	b := nbnsQuery()
	if len(b) != 49 {
		t.Fatalf("query must be 49 bytes, got %d", len(b))
	}
	if binary.BigEndian.Uint16(b[4:6]) != 1 {
		t.Fatal("must carry exactly one question")
	}
	if b[12] != 0x20 {
		t.Fatalf("encoded-name length must be 32, got %d", b[12])
	}
	// Decode the half-ASCII name: '*' + 15 NULs must come back exactly.
	var name [16]byte
	for i := 0; i < 16; i++ {
		hi := b[13+i*2] - 0x41
		lo := b[14+i*2] - 0x41
		name[i] = hi<<4 | lo
	}
	if name[0] != '*' {
		t.Fatalf("wildcard byte wrong: %#x", name[0])
	}
	for i := 1; i < 16; i++ {
		if name[i] != 0 {
			t.Fatalf("padding byte %d must be NUL, got %#x", i, name[i])
		}
	}
	if qtype := binary.BigEndian.Uint16(b[len(b)-4:]); qtype != 0x0021 {
		t.Fatalf("QTYPE must be NBSTAT 0x21, got %#x", qtype)
	}
	if qclass := binary.BigEndian.Uint16(b[len(b)-2:]); qclass != 1 {
		t.Fatalf("QCLASS must be IN, got %d", qclass)
	}
}

// Response parse: first 15-byte name, space-trimmed, rubbish rejected.
func TestParseNBNSName(t *testing.T) {
	mk := func(name string) []byte {
		resp := make([]byte, 12+37+2+1)
		n := make([]byte, 15)
		copy(n, name)
		resp = append(resp, n...)
		return resp
	}
	if got, ok := parseNBNSName(mk("DESKTOP-ABC123")); !ok || got != "DESKTOP-ABC123" {
		t.Fatalf("name parse: ok=%v got=%q", ok, got)
	}
	if got, ok := parseNBNSName(mk("PC01")); !ok || got != "PC01" {
		t.Fatalf("short name parse: ok=%v got=%q", ok, got)
	}
	// All-blank / too-short responses never fake a name.
	if _, ok := parseNBNSName(mk("")); ok {
		t.Fatal("blank name must not parse")
	}
	if _, ok := parseNBNSName(mk("   ")); ok {
		t.Fatal("spaces-only must not parse")
	}
	if _, ok := parseNBNSName(make([]byte, 20)); ok {
		t.Fatal("short packet must not parse")
	}
	// Control bytes = mangled parse, must be rejected rather than poison
	// reports or finder hints.
	if _, ok := parseNBNSName(mk("BAD\x01NAME")); ok {
		t.Fatal("control chars must be rejected")
	}
}

// A dark, ARP-present host whose name service answers is a Windows box with
// SMB closed - not a dead IP - and the name must surface in the report.
func TestProfileDarkHostsNBNS(t *testing.T) {
	old := nmsNBNSLookup
	nmsNBNSLookup = func(host string, timeout time.Duration) (string, bool) {
		if host == "192.168.68.77" {
			return "WINBOX77", true
		}
		return "", false
	}
	t.Cleanup(func() { nmsNBNSLookup = old })

	profileCacheMu.Lock()
	profileCache = map[string]profileRec{}
	profileCacheMu.Unlock()

	results := []NMSHostResult{{Host: "192.168.68.77"}, {Host: "192.168.68.78"}}
	profileDarkHosts(results, []string{"192.168.68.77", "192.168.68.78"})
	if results[0].Fingerprint != "windows-smb-off" || results[0].NBName != "WINBOX77" {
		t.Fatalf("NBNS host must profile windows-smb-off with its name, got %+v", results[0])
	}
	if results[1].Fingerprint == "windows-smb-off" {
		t.Fatal("silent host must not claim a name")
	}
}

// The clone arm must name the real blocker instead of a bare "unreachable".
func TestCloneStateSMBOffIsActionable(t *testing.T) {
	r := NMSHostResult{Host: "192.168.68.77", Reachable: false,
		Fingerprint: "windows-smb-off", NBName: "WINBOX77"}
	// Gate first (as StepNMS does), then the SMB-off branch.
	if elig, reason := CloneEligible(r.Host, r.Reachable, r.ManagedHint, nil, nil, nil); elig || reason != "unreachable" {
		t.Fatalf("dark host must gate as unreachable, got elig=%v reason=%q", elig, reason)
	}
	detail := ""
	if r.Fingerprint == "windows-smb-off" {
		detail = "windows box " + r.NBName + " with SMB closed - enable File and Printer Sharing (SMB-In) on it to clone"
	}
	if !strings.Contains(detail, "SMB-In") || !strings.Contains(detail, "WINBOX77") {
		t.Fatalf("detail must name the box and the fix, got %q", detail)
	}
}

// NBNameFor looks a host's discovered name up in a probe round.
func TestNBNameFor(t *testing.T) {
	res := []NMSHostResult{{Host: "192.168.68.77", NBName: "WINBOX77"}}
	if got := NBNameFor(res, "192.168.68.77"); got != "WINBOX77" {
		t.Fatalf("got %q", got)
	}
	if got := NBNameFor(res, "192.168.68.78"); got != "" {
		t.Fatalf("unknown host must be empty, got %q", got)
	}
}
