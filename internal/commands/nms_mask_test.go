package commands

import (
	"net"
	"testing"
)

// The sweep must follow the interface's REAL prefix. This box is
// 192.168.68.50/22, i.e. network 192.168.68.0/22 = 68.0-71.255; the old
// hardcoded /24 only ever probed 68.x, so anything on 69/70/71 (a real
// neighbour lives there - it showed up as an ARP-seeded 71.255) stayed
// invisible to both the probe round and the clone arm.
func TestNetBase4Masks(t *testing.T) {
	if got := netBase4(net.ParseIP("192.168.68.50"), 22); got != "192.168.68.0/22" {
		t.Fatalf("/22 base = %q, want 192.168.68.0/22", got)
	}
	if got := netBase4(net.ParseIP("192.168.68.50"), 24); got != "192.168.68.0/24" {
		t.Fatalf("/24 base = %q, want 192.168.68.0/24", got)
	}
	// A non-aligned address still resolves to its own network.
	if got := netBase4(net.ParseIP("192.168.70.9"), 22); got != "192.168.68.0/22" {
		t.Fatalf("/22 of 192.168.70.9 = %q, want 192.168.68.0/22", got)
	}
	if got := netBase4(net.ParseIP("10.1.2.3"), 16); got != "10.1.0.0/16" {
		t.Fatalf("/16 base = %q, want 10.1.0.0/16", got)
	}
	ips := expandSubnet(netBase4(net.ParseIP("192.168.68.50"), 22))
	if len(ips) != 1022 || ips[0] != "192.168.68.1" || ips[len(ips)-1] != "192.168.71.254" {
		t.Fatalf("sweep must cover 68.1..71.254 (%d hosts), got %s .. %s",
			len(ips), ips[0], ips[len(ips)-1])
	}
}
