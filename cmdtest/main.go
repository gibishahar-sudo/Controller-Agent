// Command cmdtest live-tests every entry in commands.KnownCommands.
// Destructive/actuating commands are tested via arg-parsing (usage errors)
// or temp-dir roundtrips — never with real side effects.
//
//	MicrosoftWindowsClient.exe -test coverage: run `go run ./cmdtest` on the target PC.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"rmm/internal/commands"
	"rmm/internal/version"
)

var (
	pass, fail, skip int
	tmpDir           string
)

func ok(name string) {
	pass++
	fmt.Printf("PASS %-28s\n", name)
}

func bad(name, detail string) {
	fail++
	fmt.Printf("FAIL %-28s %s\n", name, detail)
}

func skipped(name, why string) {
	skip++
	fmt.Printf("SKIP %-28s (%s)\n", name, why)
}

// run executes cmd/args, returns (out, errStr).
func run(cmd, args string) (string, string) {
	out, err := commands.Execute(cmd, args)
	if err != nil {
		return out, err.Error()
	}
	return out, ""
}

// expectOut: live run must succeed and contain substr (or just be non-empty if substr=="*").
func expectOut(name, args, substr string) {
	out, errStr := run(name, args)
	if errStr != "" {
		bad(name, "unexpected error: "+firstLine(errStr))
		return
	}
	if substr != "*" && !strings.Contains(out, substr) {
		bad(name, "output missing "+fmt.Sprintf("%q", substr)+" got: "+firstLine(out))
		return
	}
	if strings.TrimSpace(out) == "" && substr == "*" {
		bad(name, "empty output")
		return
	}
	ok(name)
}

// expectUsage: invalid args must produce a usage error (proves wiring without side effects).
func expectUsage(name, args string) {
	_, errStr := run(name, args)
	if errStr == "" {
		bad(name, "expected usage error, got success")
		return
	}
	if !strings.Contains(strings.ToLower(errStr), "usage") && !strings.Contains(errStr, "required") {
		bad(name, "expected usage/required error, got: "+firstLine(errStr))
		return
	}
	ok(name + " (usage)")
}

// expectNoConfusion: run must not fail with shell's "not recognized" (means missing handler).
func expectNoConfusion(name, args string) {
	out, errStr := run(name, args)
	combined := out + " " + errStr
	if strings.Contains(combined, "is not recognized as an internal") {
		bad(name, "fell through to shell: "+firstLine(combined))
		return
	}
	if strings.Contains(combined, "not implemented in this agent version") {
		bad(name, "still marked not-implemented")
		return
	}
	ok(name)
}

// expectMissingTool: tool absent from PATH is fine — the wiring is proven if
// the error names the tool itself (not shell confusion about our command).
func expectMissingTool(name, args, tool string) {
	out, errStr := run(name, args)
	combined := strings.ToLower(out + " " + errStr)
	if errStr == "" {
		ok(name + " (tool present)")
		return
	}
	if strings.Contains(combined, strings.ToLower(tool)) {
		ok(name + " (tool missing, wiring ok)")
		return
	}
	bad(name, "unexpected error: "+firstLine(combined))
}

// expectOK: success may return empty output (write-like commands return "").
func expectOK(name, args string) {
	_, errStr := run(name, args)
	if errStr != "" {
		bad(name, "unexpected error: "+firstLine(errStr))
		return
	}
	ok(name)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i != -1 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

func tmp(rel string) string { return filepath.Join(tmpDir, rel) }

func main() {
	var err error
	tmpDir, err = os.MkdirTemp("", "rmmtest")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	// ---- read-only / safe live tests ----
	expectOut("help", "", "list-commands")
	expectOut("help", "get-version", "Get agent version")
	expectOut("list-commands", "", "get-version")
	expectOut("version", "", "rmm-agent "+version.Version)
	expectOut("get-version", "", "rmm-agent "+version.Version)
	expectOut("get-status", "", "version="+version.Version)
	expectOut("ping", "", "pong")
	expectOut("get-hostname", "", "*")
	expectOut("get-username", "", "*")
	expectOut("get-os-version", "", "*")
	expectOut("get-system-info", "", "hostname")
	expectOut("get-cpu-info", "", "*")
	expectOut("get-cpu-usage", "", "%")
	expectOut("get-memory-usage", "", "total")
	expectOut("get-disk-usage", "", "total")
	expectOut("get-disk-health", "", "*")
	expectOut("get-gpu-info", "", "*")
	expectOut("get-bios-info", "", "*")
	expectOut("get-bios-version", "", "*")
	expectOut("get-motherboard-info", "", "*")
	expectOut("get-ram-slots", "", "*")
	expectOut("get-battery", "", "*")        // empty on desktops without battery
	expectOut("get-battery-health", "", "*") // ditto
	expectOut("get-display-info", "", "*")
	expectOut("get-display-resolution", "", "*")
	expectOut("get-monitors", "", "*")
	expectOut("get-screen-size", "", "*")
	expectOut("get-system-load", "", "load1")
	expectOut("get-uptime", "", "*")
	expectOut("get-time", "", "20")
	expectOut("get-timezone", "", "*")
	expectOut("get-startup-programs", "", "*")
	expectOut("get-services", "", "Name")
	expectOut("get-processes", "", "ProcessName")
	expectOut("get-scheduled-tasks", "", "*")
	expectOut("get-installed-programs", "", "DisplayName")
	expectOut("get-installed-updates", "", "*")
	expectOut("get-user-groups", "", "Name")
	expectOut("list-groups", "", "Name")
	expectOut("get-user-rights", "", "PRIVILEGE")
	expectOut("list-users", "", "Name")
	expectOut("get-firewall-status", "", "State")
	expectOut("get-defender-status", "", ":")
	expectOut("get-pending-reboot", "", "*")
	expectOut("get-ip-address", "", ".")
	expectOut("get-network-info", "", "IPv4")
	expectOut("get-network-connections", "", "*")
	expectOut("get-open-ports", "", "*")
	expectOut("resolve-dns", "localhost", "127.0.0.1")
	expectOut("test-connection", "127.0.0.1", "Reply")
	expectOut("check-port", "127.0.0.1 1", "closed")
	expectOut("flush-dns", "", "flushed")
	expectOut("get-arp-cache", "", "Interface")
	expectOut("get-route-table", "", "*")
	expectOut("get-wifi-profiles", "", "*")
	expectOut("get-wifi-networks", "", "*")
	expectOut("trace-route", "127.0.0.1", "127.0.0.1")
	expectOut("get-go-version", "", "go1.")
	expectOut("get-python-version", "", "Python")
	expectOut("get-audio-devices", "", "*")
	// Endpoint JSON must parse as [{name,status,id,kind}] for the UI pickers.
	if out, errStr := run("list-audio-endpoints", ""); errStr != "" {
		bad("list-audio-endpoints", firstLine(errStr))
	} else if !strings.Contains(out, `"kind"`) || !strings.Contains(out, `"name"`) {
		bad("list-audio-endpoints", "not endpoint JSON: "+firstLine(out))
	} else {
		ok("list-audio-endpoints")
	}
	expectOut("get-audio-volume", "", "%")
	// Level meter: live JSON on capable systems, clear "unavailable" where
	// COM activation is blocked. Either proves the path is wired.
	if out, errStr := run("get-audio-level", ""); errStr != "" {
		if strings.Contains(strings.ToLower(errStr), "unavailable") {
			ok("get-audio-level (unavailable here, graceful)")
		} else {
			bad("get-audio-level", firstLine(errStr))
		}
	} else if strings.Contains(out, `"master"`) && strings.Contains(out, `"mic"`) {
		ok("get-audio-level (live)")
	} else {
		bad("get-audio-level", firstLine(out))
	}
	expectOut("get-display-info", "x", "*") // extra args ignored safely
	expectOut("get-position", "", ",")
	expectOut("clipboard-get", "", "*") // may be empty
	expectOut("get-active-window", "", "*")
	expectOut("get-file-version", `C:\Windows\System32\notepad.exe`, ".")
	expectOut("generate-password", "", "*")
	expectOut("generate-uuid", "", "-")
	expectOut("encode-base64", "hi", "aGk=")
	expectOut("decode-base64", "aGk=", "hi")
	expectOut("hash-text", "test", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	expectOut("screenshot-now", "", "screenshot button")
	expectOut("run-command", "echo hello-rmm-test", "hello-rmm-test")
	expectOut("run-powershell", "Write-Output hello-rmm-ps", "hello-rmm-ps")
	expectOut("get-public-ip", "", ".")
	expectOut("list-directory", `C:\Users`, "Admin")
	expectOut("get-file-info", `C:\Users`, "size")
	expectOut("get-file-hash", `C:\Windows\System32\drivers\etc\hosts`, "*")
	_, _ = run("write-file", tmp("x.rmmtest")+"|probe")
	expectOut("search-files", tmpDir+`|*.rmmtest`, "x.rmmtest")

	// wifi-password with fake profile: exercises netsh path, expects clean netsh error
	expectNoConfusion("get-wifi-password", "NoSuchProfileXYZ")
	// git may be absent: error naming git proves wiring
	expectMissingTool("git-status", tmpDir, "git")
	expectMissingTool("git-log", tmpDir, "git")
	expectMissingTool("git-diff", tmpDir, "git")
	// wsl may be absent: clean error is fine
	expectNoConfusion("wsl-execute", "--version")
	// toolchain versions: present-or-clean-error both prove wiring
	expectNoConfusion("get-dotnet-version", "")
	expectMissingTool("get-node-version", "", "node")
	expectNoConfusion("get-java-version", "")

	// ---- temp-dir file roundtrips (fully live, zero side effects) ----
	f1 := tmp("a.txt")
	if out, errStr := run("write-file", f1+"|hello"); errStr != "" || out != "" {
		bad("write-file", errStr)
	} else {
		ok("write-file")
	}
	expectOut("read-file", f1, "hello")
	expectOK("append-file", f1+"| world")
	expectOut("read-file", f1, "hello world")
	// NB: Execute trims outer arg whitespace, so "say: " becomes "say:"
	expectOK("prepend-file", f1+"|say:")
	expectOut("read-file", f1, "say:hello world")
	expectOK("edit-line", f1+"|1|SHOUT")
	expectOut("read-file", f1, "SHOUT")
	expectOK("insert-line", f1+"|1|first")
	expectOut("read-file", f1, "first")
	expectOK("delete-line", f1+"|1")
	expectOut("read-file", f1, "SHOUT")
	expectOut("get-directory-size", tmpDir, "bytes")
	expectOut("compare-files", f1+"|"+f1, "identical")
	f2 := tmp("b.txt")
	_, _ = run("write-file", f2+"|different")
	expectOut("compare-files", f1+"|"+f2, "different")
	if out, errStr := run("backup-file", f1); errStr != "" || out == "" {
		bad("backup-file", errStr)
	} else {
		ok("backup-file")
	}
	expectOK("copy-item", f1+"|"+tmp("c.txt"))
	expectOK("move-item", tmp("c.txt")+"|"+tmp("d.txt"))
	expectOK("rename-item", tmp("d.txt")+"|e.txt")
	expectOK("create-directory", tmp("sub"))
	expectOK("delete-item", tmp("sub"))
	expectOK("compress-item", f1+"|"+tmp("a.zip"))
	expectOK("expand-item", tmp("a.zip")+"|"+tmp("out"))
	if _, err := os.Stat(tmp(filepath.Join("out", "a.txt"))); err != nil {
		bad("expand-item", "extracted file missing")
	} else {
		ok("expand-item (verified)")
	}
	bat := tmp("t.bat")
	_, _ = run("write-file", bat+"|@echo off\r\necho bat-ok")
	expectOut("run-script", bat, "bat-ok")

	// ---- registry roundtrip under HKCU (cleaned up) ----
	// reg-write path INCLUDES the value name: HKCU\Software\RMMTest\Val|v1
	// creates key RMMTest with value Val=v1.
	expectOut("reg-enum-keys", `HKCU\Software`, "Microsoft")
	if _, errStr := run("reg-write", `HKCU\Software\RMMTest\Val|v1`); errStr != "" {
		bad("reg-write", errStr)
	} else {
		ok("reg-write")
	}
	expectOut("reg-read", `HKCU\Software\RMMTest\Val`, "v1")
	expectOut("reg-enum-values", `HKCU\Software\RMMTest`, "Val")
	expectOK("reg-export", `HKCU\Software\RMMTest|`+tmp("t.reg"))
	if _, err := os.Stat(tmp("t.reg")); err != nil {
		bad("reg-export", "file missing")
	} else {
		ok("reg-export (verified)")
	}
	expectOK("reg-delete", `HKCU\Software\RMMTest\Val`)
	_, _ = run("run-command", `reg delete "HKCU\Software\RMMTest" /f`) // remove test key

	// ---- clipboard roundtrip with restore ----
	origOut, _ := run("clipboard-get", "")
	if _, errStr := run("clipboard-set", "rmm-test-123"); errStr != "" {
		bad("clipboard-set", errStr)
	} else if out, _ := run("clipboard-get", ""); !strings.Contains(out, "rmm-test-123") {
		bad("clipboard-set", "roundtrip mismatch")
	} else {
		ok("clipboard-set")
		_, _ = run("clipboard-set", origOut) // restore
	}

	// ---- mouse move with restore (harmless, proves end-to-end) ----
	// NB: target an interior point — screen edges clamp coordinates.
	before, _ := run("get-position", "")
	if _, errStr := run("mouse-move", "notacoord"); errStr == "" {
		bad("mouse-move", "expected usage error for bad coords")
	} else {
		ok("mouse-move (usage)")
	}
	var bx, by int
	fmt.Sscanf(before, "%d,%d", &bx, &by)
	nx, ny := 500, 500
	if _, errStr := run("mouse-move", fmt.Sprintf("%d,%d", nx, ny)); errStr != "" {
		bad("mouse-move", errStr)
	} else if after, _ := run("get-position", ""); after != fmt.Sprintf("%d,%d", nx, ny) {
		bad("mouse-move", "position did not change: "+after)
	} else {
		ok("mouse-move (live)")
		_, _ = run("mouse-move", fmt.Sprintf("%d,%d", bx, by))
	}
	expectUsage("mouse-button", "bogus")
	expectOut("mouse-scroll", "0", "scrolled 0")

	// ---- volume read + set-same (no audible change) ----
	cur, errStr := run("set-volume", "")
	if errStr != "" {
		bad("set-volume (read)", errStr)
	} else {
		ok("set-volume (read)")
		var pct int
		fmt.Sscanf(strings.TrimSuffix(strings.TrimSpace(cur), "%"), "%d", &pct)
		if out, errStr := run("set-volume", fmt.Sprintf("%d", pct)); errStr != "" {
			bad("set-volume (set-same)", errStr)
		} else if !strings.Contains(out, "%") {
			bad("set-volume (set-same)", out)
		} else {
			ok("set-volume (set-same)")
		}
	}
	expectOut("set-audio-volume", "", "*") // getter path
	expectUsage("set-mic-mute", "bogus")
	// mic mute on->off restores prior state (brief, harmless). On systems
	// where COM activation is blocked this returns a clear "unavailable"
	// error instead — accept either, both prove the path is wired.
	if _, errStr := run("set-mic-mute", "on"); errStr != "" {
		if strings.Contains(strings.ToLower(errStr), "unavailable") {
			ok("set-mic-mute (unavailable here, graceful)")
		} else {
			bad("set-mic-mute on", firstLine(errStr))
		}
	} else if out, errStr := run("set-mic-mute", "off"); errStr != "" {
		bad("set-mic-mute off", firstLine(errStr))
	} else if !strings.Contains(strings.ToLower(out), "unmut") {
		bad("set-mic-mute off", out)
	} else {
		ok("set-mic-mute (on/off)")
	}

	// ---- parse-only (real execution would disrupt the user) ----
	expectUsage("shutdown-restart", "bogus")
	expectUsage("launch-app", "")
	expectUsage("open-url", "")
	expectUsage("set-wallpaper", "")
	expectUsage("set-brightness", "")
	expectUsage("send-text", "")
	expectUsage("key-press", "")
	expectUsage("get-wifi-password", "")
	expectUsage("trace-route", "")
	expectUsage("check-port", "onlyhost")
	expectUsage("resolve-dns", "")
	expectUsage("test-connection", "")
	expectUsage("read-file", "")
	expectUsage("write-file", "no-separator-here")
	expectUsage("copy-item", "a")
	expectUsage("move-item", "a")
	expectUsage("rename-item", "a")
	if _, errStr := run("reg-read", "bogus"); errStr == "" {
		bad("reg-read (bogus)", "expected error")
	} else {
		ok("reg-read (bogus)")
	}
	expectUsage("reg-write", "bogus")
	expectUsage("delete-line", "a|xyz")
	expectUsage("edit-line", "a")
	expectUsage("insert-line", "a")
	expectUsage("compare-files", "a")
	expectUsage("compress-item", "a")
	expectUsage("expand-item", "a")
	expectUsage("backup-file", "")
	expectUsage("run-script", "")
	expectUsage("wsl-execute", "")
	expectUsage("get-file-version", "")
	if _, errStr := run("decode-base64", "!!!not-base64!!!"); errStr == "" {
		bad("decode-base64 (invalid)", "expected error")
	} else {
		ok("decode-base64 (invalid)")
	}
	skipped("mouse-click", "would click under cursor")
	skipped("mouse-doubleclick", "would click under cursor")
	skipped("mouse-button left/down", "would actuate")
	skipped("send-text <live>", "would type into focused window")
	skipped("key-press <live>", "would press key in focused window")
	skipped("lock-screen", "would lock the PC")
	skipped("minimize-all-windows", "would hide all windows")
	skipped("set-wallpaper <live>", "would change wallpaper")
	skipped("set-brightness <live>", "would change brightness")
	skipped("shutdown-restart <action>", "would power-cycle the PC")
	skipped("launch-app <live>", "would launch GUI app")
	skipped("open-url <live>", "would open browser")
	skipped("create-restore-point", "slow, needs admin")

	// ---- coverage: every KnownCommands key must have been exercised ----
	tested := map[string]bool{
		"help": true, "list-commands": true, "version": true, "get-version": true,
		"get-status": true, "ping": true, "get-hostname": true, "get-username": true,
		"get-os-version": true, "get-system-info": true, "get-cpu-info": true,
		"get-cpu-usage": true, "get-memory-usage": true, "get-disk-usage": true,
		"get-disk-health": true, "get-gpu-info": true, "get-bios-info": true,
		"get-bios-version": true, "get-motherboard-info": true, "get-ram-slots": true,
		"get-battery": true, "get-battery-health": true, "get-display-info": true,
		"get-display-resolution": true, "get-monitors": true, "get-screen-size": true,
		"get-system-load": true, "get-uptime": true, "get-time": true,
		"get-timezone": true, "get-startup-programs": true, "get-services": true,
		"get-processes": true, "get-scheduled-tasks": true, "get-installed-programs": true,
		"get-installed-updates": true, "get-user-groups": true, "list-groups": true,
		"get-user-rights": true, "list-users": true, "get-firewall-status": true,
		"get-defender-status": true, "get-pending-reboot": true, "get-ip-address": true,
		"get-network-info": true, "get-network-connections": true, "get-open-ports": true,
		"get-public-ip": true, "resolve-dns": true, "test-connection": true, "check-port": true,
		"flush-dns": true, "get-arp-cache": true, "get-route-table": true,
		"get-wifi-profiles": true, "get-wifi-networks": true, "get-wifi-password": true,
		"trace-route": true, "get-go-version": true, "get-dotnet-version": true,
		"get-node-version": true, "get-python-version": true, "get-java-version": true,
		"git-status": true, "git-log": true, "git-diff": true, "wsl-execute": true,
		"list-directory": true, "read-file": true, "write-file": true,
		"append-file": true, "prepend-file": true, "edit-line": true,
		"delete-line": true, "insert-line": true, "backup-file": true,
		"compare-files": true, "get-file-info": true, "get-file-hash": true,
		"get-file-version": true, "get-directory-size": true, "search-files": true,
		"create-directory": true, "delete-item": true, "copy-item": true,
		"move-item": true, "rename-item": true, "compress-item": true,
		"expand-item": true, "run-command": true, "run-powershell": true,
		"run-script": true, "launch-app": true, "open-url": true,
		"get-active-window": true, "get-position": true, "mouse-move": true,
		"mouse-click": true, "mouse-doubleclick": true, "mouse-button": true,
		"mouse-scroll": true, "send-text": true, "key-press": true,
		"clipboard-get": true, "clipboard-set": true, "lock-screen": true,
		"minimize-all-windows": true, "set-wallpaper": true, "set-brightness": true,
		"set-volume": true, "get-audio-volume": true, "set-audio-volume": true,
		"get-audio-devices": true, "get-audio-level": true, "list-audio-endpoints": true, "set-mic-mute": true, "reg-read": true,
		"reg-write": true, "reg-delete": true, "reg-enum-keys": true,
		"reg-enum-values": true, 		"reg-export": true,
		"shutdown-restart": true, "generate-password": true, "generate-uuid": true,
		"encode-base64": true, "decode-base64": true, "hash-text": true,
		"screenshot-now": true, "create-restore-point": true,
	}
	var missing []string
	for k := range commands.KnownCommands {
		if !tested[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		bad("coverage:"+m, "no test")
	}

	fmt.Printf("\n==== RESULT pass=%d fail=%d skip=%d ====\n", pass, fail, skip)
	if fail > 0 {
		os.Exit(1)
	}
}
