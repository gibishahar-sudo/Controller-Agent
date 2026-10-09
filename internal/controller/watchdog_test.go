package controller

import (
	"strings"
	"testing"
)

// Flash-free launcher pieces (v1.46.96): Run values, task XML, and the
// Run-value parser must agree exactly, or persistence silently keeps
// flashing consoles.
func TestWatchRunValue(t *testing.T) {
	got := watchRunValue(`C:\a b\c.vbs`)
	if got != `wscript.exe //B //Nologo "C:\a b\c.vbs"` {
		t.Fatalf("run value = %q", got)
	}
}

func TestPs1FromRun(t *testing.T) {
	ps := ps1FromRun(`powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\a b\controller-watchdog.ps1"`)
	if ps != `C:\a b\controller-watchdog.ps1` {
		t.Fatalf("powershell form: %q", ps)
	}
	got := ps1FromRun(`wscript.exe //B //Nologo "C:\a b\controller-watchdog.vbs"`)
	if got != `C:\a b\controller-watchdog.ps1` {
		t.Fatalf("wscript spaced form: %q", got)
	}
	for _, bad := range []string{"", "wscript.exe //B", `powershell -File`, "notepad.exe x"} {
		if ps1FromRun(bad) != "" {
			t.Fatalf("%q must not parse", bad)
		}
	}
}

func TestMigrateTaskXML(t *testing.T) {
	const src = `<Task><Actions><Exec><Command>powershell</Command><Arguments>-NoProfile -File "C:\a b\controller-watchdog.ps1"</Arguments></Exec></Actions></Task>`
	got, changed := migrateTaskXML(src, `C:\a b\controller-watchdog.vbs`)
	if !changed {
		t.Fatal("must migrate")
	}
	if !strings.Contains(got, "<Command>wscript</Command>") {
		t.Fatalf("action: %q", got)
	}
	if !strings.Contains(got, `//B //Nologo "C:\a b\controller-watchdog.vbs"`) {
		t.Fatalf("args: %q", got)
	}
	again, changed := migrateTaskXML(got, `C:\a b\controller-watchdog.vbs`)
	if changed || again != got {
		t.Fatal("migration must be idempotent")
	}
	foreign := `<Task><Actions><Exec><Command>notepad.exe</Command><Arguments>x</Arguments></Exec></Actions></Task>`
	if out, changed := migrateTaskXML(foreign, `C:\v.vbs`); changed || out != foreign {
		t.Fatal("foreign task must pass through untouched")
	}
}

func TestWatchVbsText(t *testing.T) {
	if !strings.Contains(watchVbsText, `", 0, False`) || !strings.Contains(watchVbsText, "ScriptFullName") {
		t.Fatalf("vbs must run the sibling hidden: %q", watchVbsText)
	}
}
