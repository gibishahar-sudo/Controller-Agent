package commands

// NBNS (NetBIOS Name Service, UDP 137) probe.
//
// Why this exists: a stock Windows 10/11 box answers NOTHING on 445/135/139/
// 3389 unless File and Printer Sharing is enabled - which is OFF by default.
// To the TCP sweep such a box is indistinguishable from an empty IP, so the
// monitor reported "unreachable" and the clone arm skipped it forever. The
// name service is the one Windows signal that survives the default firewall:
// a wildcard NBSTAT query returns the box's computer name.
//
// That name does double duty:
//   - fingerprint: NBNS answer => Windows, with SMB closed (a real target
//     whose blocker is a switch to flip, not a dead IP)
//   - the finder's best Tier-0 word, same as nbtstat -A but in-process
//
// UDP 137 has no TCP-timeout semantics, so every query is hard-bounded and a
// silent box costs one 700ms wait, never a stall.

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// nmsNBNSLookup queries a host's name service. Var so tests stay hermetic.
var nmsNBNSLookup = nbnsLookup

// nbnsLookup sends one wildcard NBSTAT query and returns the computer name.
func nbnsLookup(ip string, timeout time.Duration) (string, bool) {
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 700 * time.Millisecond
	}
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ip, "137"))
	if err != nil {
		return "", false
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(nbnsQuery()); err != nil {
		return "", false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 64 {
		return "", false
	}
	return parseNBNSName(buf[:n])
}

// nbnsQuery builds the wildcard NBSTAT request: transaction id, one
// question for "*" padded to 16 bytes, QTYPE NBSTAT (0x0021), QCLASS IN.
// Pure, testable.
func nbnsQuery() []byte {
	b := make([]byte, 0, 50)
	b = append(b, 0x13, 0x37)       // transaction id
	b = append(b, 0x00, 0x00)       // flags: query
	b = append(b, 0x00, 0x01)       // one question
	b = append(b, 0x00, 0x00)       // answers
	b = append(b, 0x00, 0x00)       // authority
	b = append(b, 0x00, 0x00)       // additional
	b = append(b, 0x20)             // encoded name length (32 nibbles)
	// 16-byte wildcard name "*" + 15 NULs, each byte split into two nibbles
	// biased by 'A'.
	name := make([]byte, 16)
	name[0] = '*'
	for i := range name {
		hi, lo := name[i]>>4, name[i]&0x0f
		b = append(b, hi+0x41, lo+0x41)
	}
	b = append(b, 0x00, 0x21) // QTYPE NBSTAT
	b = append(b, 0x00, 0x01) // QCLASS IN
	return b
}

// parseNBNSName extracts the first (computer) name from an NBSTAT response.
// Layout: 12-byte header + 37-byte echoed question + 2-byte answer count,
// then one name-count byte, then 15-byte names (15 name + 2 type + 2 flags
// each), then MAC + statistics. Pure, testable.
func parseNBNSName(resp []byte) (string, bool) {
	const off = 12 + 37 + 2 + 1
	if len(resp) < off+15 {
		return "", false
	}
	raw := resp[off : off+15]
	// Names are space-padded and may carry a suffix like <20>; keep the
	// first label only.
	if i := indexByte(raw, 0x20); i >= 0 {
		raw = raw[:i]
	}
	name := strings.TrimRight(string(raw), " \x00")
	if name == "" {
		return "", false
	}
	// Reject obvious rubbish (control chars) - a mangled parse must not
	// poison reports or finder hints.
	for _, c := range name {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	_ = binary.BigEndian // layout is byte-oriented; kept explicit
	return name, true
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// NBNameFor returns the discovered NetBIOS computer name for a host from
// the last probe round (empty when unknown).
func NBNameFor(results []NMSHostResult, host string) string {
	for _, r := range results {
		if strings.EqualFold(r.Host, host) {
			return r.NBName
		}
	}
	return ""
}
