package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHouseLines(t *testing.T) {
	got := parseHouseLines("# comment\n\n10.0.0.5\n10.0.0.6:4443\n")
	if len(got) != 2 || got[0] != "10.0.0.5:4444" || got[1] != "10.0.0.6:4443" {
		t.Fatalf("bad parse: %q", got)
	}
}

func TestDialAddrsMultiHouse(t *testing.T) {	houses := []string{"10.0.0.5:4444", "10.0.0.6:4444"}
	addrs := dialAddrs("10.0.0.9:4444", houses)
	if len(addrs) == 0 || addrs[0] != "10.0.0.9:4444" {
		t.Fatalf("primary must come first: %q", addrs)
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		if seen[a] {
			t.Fatalf("duplicate addr %s in %q", a, addrs)
		}
		seen[a] = true
	}
	for _, want := range []string{"10.0.0.5:4444", "10.0.0.5:443", "10.0.0.6:4444", "127.0.0.1:4444"} {
		if !seen[want] {
			t.Fatalf("missing %s in %q", want, addrs)
		}
	}
}

// Stale lastgood must never lead the race: closed port and garbage file
// read empty; a live loopback listener reads back.
func TestLoadLastGoodValidates(t *testing.T) {
	dir := t.TempDir()
	old := lastGoodFileOverride
	lastGoodFileOverride = filepath.Join(dir, "lastgood.txt")
	t.Cleanup(func() { lastGoodFileOverride = old })

	if got := loadLastGood(); got != "" {
		t.Fatalf("missing file must read empty, got %q", got)
	}
	if err := os.WriteFile(lastGoodFileOverride, []byte("garbage-no-port\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := loadLastGood(); got != "" {
		t.Fatalf("garbage must read empty, got %q", got)
	}
	if err := os.WriteFile(lastGoodFileOverride, []byte("127.0.0.1:9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := loadLastGood(); got != "" {
		t.Fatalf("closed port must read empty, got %q", got)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.WriteFile(lastGoodFileOverride, []byte(ln.Addr().String()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := loadLastGood(); got != ln.Addr().String() {
		t.Fatalf("live port must read back, got %q", got)
	}
}
