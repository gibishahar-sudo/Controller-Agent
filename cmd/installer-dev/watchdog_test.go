package main

import (
	"strings"
	"testing"
)

// Flash-free launcher (v1.46.96): the .vbs must run the sibling .ps1
// hidden with no console of its own, and derive the path from its own
// location (per-user blender dir varies).
func TestControllerWatchdogVbs(t *testing.T) {
	v := controllerWatchdogVbsText
	if !strings.Contains(v, `CreateObject("Wscript.Shell")`) {
		t.Fatal("vbs must shell out")
	}
	if !strings.Contains(v, `", 0, False`) {
		t.Fatal("vbs must run hidden+detached")
	}
	if !strings.Contains(v, "ScriptFullName") || !strings.Contains(v, `& ".ps1"`) {
		t.Fatalf("vbs must derive the sibling ps1 from its own path: %q", v)
	}
	if strings.Contains(v, "C:\\") {
		t.Fatal("vbs must not hardcode paths")
	}
}

func TestWatchdogRunValue(t *testing.T) {
	got := watchdogRunValue(`C:\a b\c.vbs`)
	if got != `wscript.exe //B //Nologo "C:\a b\c.vbs"` {
		t.Fatalf("run value = %q", got)
	}
	if strings.Contains(strings.ToLower(got), "powershell") {
		t.Fatalf("run value must not spawn powershell: %q", got)
	}
}

func TestControllerTaskXML(t *testing.T) {
	got := controllerTaskXML(`C:\a b\controller-watchdog.ps1`)
	if !strings.Contains(got, "<Command>wscript</Command>") {
		t.Fatal("task action must be wscript")
	}
	if !strings.Contains(got, `//B //Nologo "C:\a b\controller-watchdog.vbs"`) {
		t.Fatalf("task must point at the sibling vbs: %q", got)
	}
	if strings.Contains(got, "<Command>powershell</Command>") {
		t.Fatal("task must not spawn powershell directly")
	}
	for _, keep := range []string{"PT15M", "SessionUnlock", "LogonTrigger", "HighestAvailable"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("task lost %q in refactor", keep)
		}
	}
}
