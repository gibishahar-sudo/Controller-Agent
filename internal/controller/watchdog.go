package controller

import "strings"

// watchVbsText MUST match installer-dev's controllerWatchdogVbsText
// (duplicated: separate binaries; keep in sync).
const watchVbsText = `' RMM controller watchdog launcher (flash-free: wscript allocates no console).
Set sh = CreateObject("Wscript.Shell")
me = WScript.ScriptFullName
ps1 = Left(me, Len(me) - 4) & ".ps1"
sh.Run "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & ps1 & """", 0, False
`

// watchRunValue builds the flash-free Run value. Pure, tested.
func watchRunValue(vbsPath string) string {
	return `wscript.exe //B //Nologo "` + vbsPath + `"`
}

// ps1FromRun extracts the watchdog .ps1 from a Run value of either form
// (powershell ... -File "P", or wscript "V" pointing at the sibling).
// "" when absent/unparseable. Pure, tested.
func ps1FromRun(val string) string {
	if i := strings.Index(val, `-File "`); i >= 0 {
		rest := val[i+len(`-File "`):]
		if j := strings.Index(rest, `"`); j > 0 {
			return rest[:j]
		}
		return ""
	}
	// wscript form: scan quoted segments (Fields would shred spaced paths).
	for i := 0; i < len(val); i++ {
		if val[i] != '"' {
			continue
		}
		j := strings.Index(val[i+1:], `"`)
		if j < 0 {
			break
		}
		p := val[i+1 : i+1+j]
		if strings.HasSuffix(strings.ToLower(p), ".vbs") {
			return p[:len(p)-4] + ".ps1"
		}
		i += j + 1
	}
	return ""
}

// replaceXMLTag swaps the first <tag>...</tag> content. Pure, tested.
func replaceXMLTag(s, tag, val string) (string, bool) {
	open := "<" + tag + ">"
	i := strings.Index(s, open)
	if i < 0 {
		return s, false
	}
	end := "</" + tag + ">"
	j := strings.Index(s[i:], end)
	if j < 0 {
		return s, false
	}
	return s[:i] + open + val + s[i+j:], true
}

// migrateTaskXML swaps a task export's powershell action for the wscript
// launcher, preserving every trigger/setting (pure, tested). Only our
// watchdog task qualifies (name guard); already-migrated XML passes
// through unchanged. Returns (newXML, changed).
func migrateTaskXML(xmlText, vbsPath string) (string, bool) {
	if !strings.Contains(strings.ToLower(xmlText), "controller-watchdog") {
		return xmlText, false
	}
	if strings.Contains(xmlText, "<Command>wscript</Command>") {
		return xmlText, false
	}
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(`//B //Nologo "` + vbsPath + `"`)
	out, c1 := replaceXMLTag(xmlText, "Command", "wscript")
	out, c2 := replaceXMLTag(out, "Arguments", esc)
	return out, c1 && c2
}
