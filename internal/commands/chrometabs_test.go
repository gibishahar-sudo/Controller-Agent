package commands

import (
	"strings"
	"testing"
)

func TestFormatChromeTabs(t *testing.T) {
	if got := formatChromeTabs(""); got != "no Chrome windows open" {
		t.Fatalf("empty: %q", got)
	}
	if got := formatChromeTabs("  \r\n\n"); got != "no Chrome windows open" {
		t.Fatalf("blanks: %q", got)
	}
	got := formatChromeTabs("Inbox - Gmail - Google Chrome\r\nYouTube\r\n\r\n  \r\nMaps\r\n")
	want := "3 Chrome window(s):\n1. Inbox - Gmail - Google Chrome\n2. YouTube\n3. Maps"
	if got != want {
		t.Fatalf("numbered:\n%s\nwant:\n%s", got, want)
	}
}

func TestFormatChromeTabsSingle(t *testing.T) {
	got := formatChromeTabs("Bank - Google Chrome\n")
	want := "1 Chrome window(s):\n1. Bank - Google Chrome"
	if got != want {
		t.Fatalf("single:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "\r") {
		t.Fatalf("CR leaked: %q", got)
	}
}
