package commands

import (
	"strings"
	"testing"
)

func TestParseHistoryArgs(t *testing.T) {
	n, ref := parseHistoryArgs("")
	if n != 20 || ref != "" {
		t.Fatalf("default: %d %q", n, ref)
	}
	n, ref = parseHistoryArgs("5")
	if n != 5 || ref != "" {
		t.Fatalf("count: %d %q", n, ref)
	}
	n, ref = parseHistoryArgs("10 Work")
	if n != 10 || ref != "Work" {
		t.Fatalf("count+ref: %d %q", n, ref)
	}
	n, ref = parseHistoryArgs("personal")
	if n != 20 || ref != "personal" {
		t.Fatalf("ref-only: %d %q", n, ref)
	}
	n, _ = parseHistoryArgs("9999")
	if n != 50 {
		t.Fatalf("cap: %d", n)
	}
	n, _ = parseHistoryArgs("0")
	if n != 1 {
		t.Fatalf("floor: %d", n)
	}
}

func TestChromeProfileName(t *testing.T) {
	ls := []byte(`{"info_cache":{"Default":{"name":"Personal","user_name":"dave@gmail.com"},"Profile 1":{"name":"Work","user_name":"d@corp.com"}}}`)
	name, email := chromeProfileName(ls, "Default")
	if name != "Personal" || email != "dave@gmail.com" {
		t.Fatalf("default: %q %q", name, email)
	}
	name, email = chromeProfileName(ls, "Profile 1")
	if name != "Work" || email != "d@corp.com" {
		t.Fatalf("p1: %q %q", name, email)
	}
	name, _ = chromeProfileName(ls, "Profile 9")
	if name != "Profile 9" {
		t.Fatalf("unknown falls back to dir: %q", name)
	}
	name, _ = chromeProfileName([]byte("not json"), "Default")
	if name != "Default" {
		t.Fatalf("bad json falls back: %q", name)
	}
}

func TestListAndMatchProfiles(t *testing.T) {
	ls := []byte(`{"info_cache":{"Default":{"name":"Personal","user_name":"dave@gmail.com"},"Profile 1":{"name":"Work","user_name":"d@corp.com"}}}`)
	have := map[string]bool{"Default": true, "Profile 1": true, "System Profile": true}
	profiles := buildProfileList(
		[]string{"Default", "Profile 1", "Profile 2", "System Profile"},
		func(d string) bool { return have[d] },
		ls,
	)
	if len(profiles) != 2 || profiles[0].dir != "Default" || profiles[1].dir != "Profile 1" {
		t.Fatalf("order/gate: %+v", profiles)
	}
	if profiles[0].name != "Personal" || profiles[0].email != "dave@gmail.com" {
		t.Fatalf("names: %+v", profiles[0])
	}
	if p, ok := matchChromeProfile(profiles, "#2"); !ok || p.dir != "Profile 1" {
		t.Fatalf("#2: %+v %v", p, ok)
	}
	if p, ok := matchChromeProfile(profiles, "work"); !ok || p.dir != "Profile 1" {
		t.Fatalf("name: %+v %v", p, ok)
	}
	if p, ok := matchChromeProfile(profiles, "dave"); !ok || p.dir != "Default" {
		t.Fatalf("email local-part: %+v %v", p, ok)
	}
	if p, ok := matchChromeProfile(profiles, "Profile 1"); !ok || p.dir != "Profile 1" {
		t.Fatalf("dir: %+v %v", p, ok)
	}
	if _, ok := matchChromeProfile(profiles, "nobody"); ok {
		t.Fatal("unknown matched")
	}
	list := formatProfileList(profiles)
	if !strings.HasPrefix(list, "profiles:\n") || !strings.Contains(list, "[Default]") || !strings.Contains(list, "[Profile 1]") {
		t.Fatalf("profile list:\n%s", list)
	}
}

func TestFormatHistoryRows(t *testing.T) {
	raw := "2026-10-07 13:09:00|https://example.com/a|Example A\r\n2026-10-07 13:08:00|https://example.com/b|Example B\n\n"
	got := formatHistoryRows(raw, 20)
	want := "1. 2026-10-07 13:09:00 | Example A | https://example.com/a\n2. 2026-10-07 13:08:00 | Example B | https://example.com/b"
	if got != want {
		t.Fatalf("rows:\n%s\nwant:\n%s", got, want)
	}
	if got := formatHistoryRows("", 20); got != "no history rows" {
		t.Fatalf("empty: %q", got)
	}
	long := "2026-10-07|https://example.com/" + strings.Repeat("x", 300) + "|T"
	got = formatHistoryRows(long, 20)
	if strings.Contains(got, strings.Repeat("x", 200)) {
		t.Fatal("url not trimmed")
	}
}
