package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf16"
)

// buildInstallCMD renders the agent install one-liner (pre-base64). The
// download verifies exact byte size with retries and refuses to execute
// short files (v1.47.3 post-mortem: iwr silently accepted an 8%
// truncated binary and Start-Process "ran" it — "the cmd doesn't
// update" with zero diagnostics). Pure, tested.
func buildInstallCMD(token, assetID string, size int64) string {
	return buildInstallCMDMode(token, assetID, size, "iwr")
}

// cmdMarker identifies the minter revision in every run (v1.47.3
// follow-up: a hand-spliced stale copy wasted an evening — the first
// output line now names exactly what is running).
const cmdMarker = "rmm-install curl/5 relaunch/2"

// ps1Marker is the same canary for the file-delivered variant (v1.47.3
// follow-up two: a 2800-char chat paste arrived with invisible damage —
// bytes that cross chat must travel over HTTPS instead, verified by
// size gates; the file's first line still self-identifies).
const ps1Marker = "rmm-install ps1/2 relaunch/2"

// installTail is the shared download-verify-elevate tail: exact-size
// retry gate, loud failure, proven whoami elevation branch. fetch is
// the download statement, sizeExpr the expected byte count (literal in
// pasted CMDs, $size in the ps1 file). One definition so the pasted and
// file variants can never drift apart. Pure, tested.
//
// Abbreviation rule (v1.47.3 follow-up, PROVED live on PS 5.1): -Wai
// (Wait), -Pa (PassThru), -Win (WindowStyle), -Pas are safe; -Wa binds
// WarningAction and throws MissingArgument — it killed the UAC relaunch
// on the first real box run. --silent rides ValueFromRemainingArguments
// into the target exe (verified: zero binding errors). New abbreviations
// must be stub-executed (Start-Process cmd.exe -ArgumentList '/c exit N'
// + exit-code assert) before they ship — the parsers can't catch binding.
func installTail(fetch, sizeExpr string) []string {
	return []string{
		`ri $o -ea 0`,
		fmt.Sprintf(`$ok=$false;for($i=0;$i -lt 3 -and !$ok;$i++){%s;if((gi $o -ea 0).Length -eq %s){$ok=$true}}`, fetch, sizeExpr),
		`if(!$ok){throw 'download incomplete'}`,
		`$a=[bool]((whoami /groups)-match'S-1-16-12288')`,
		`if($a){$c=Start-Process $o --silent -Wai -Pa -Win Hidden;'a='+$a+' e='+$c.ExitCode}else{Write-Host 'not admin - approve the UAC prompt to continue';$exe=(Get-Item $o).FullName;try{$p=Start-Process powershell -Verb RunAs -ArgumentList ('-WindowStyle Hidden -NoProfile -Command & {$c=Start-Process '''+$exe+''' --silent -Wai -Pa -Win Hidden; exit $c.ExitCode}') -Wai -Pas}catch{throw ('UAC failed ('+$_.Exception.Message+') - approve on the box screen or run from an elevated prompt')};'elevated installer exit='+$p.ExitCode}`,
	}
}

// curlFetch is the single curl download statement (plain full retries —
// NO -C - resume: the api.github.com asset endpoint honors no Range
// requests, so resume aborts with curl 33 on any stale partial, v1.47.3
// HOME box proved). authExpr/idExpr are literals in pasted CMDs,
// parenthesized expressions in the ps1 file. Pure, tested.
func curlFetch(authExpr, idExpr string) string {
	return fmt.Sprintf(`& curl.exe -sS -L --retry 2 --retry-all-errors --max-time 240 -H %s -H 'Accept: application/octet-stream' -o $o https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/%s`, authExpr, idExpr)
}

// buildInstallCMDMode renders the one-liner with a selectable fetcher:
// "iwr" (Invoke-WebRequest, simple) or "curl" (curl.exe full retries:
// plain GETs, no resume — the asset endpoint honors no Range requests).
// Elevation is explicit: .NET role check up front; non-admin relaunches
// POWERSHELL elevated (never the payload directly, so the UAC prompt
// names a familiar publisher) and reports the child's exit code; denial
// throws loudly. The triple-quote join keeps the whole template free of
// double quotes (the outer -EncodedCommand shape forbids them).
// Templates stay lean: headers/URL inline, abbreviated params (-Wai -Pa
// -Win), gi -ea instead of Test-Path. Floor is ~650 raw chars (token +
// URL + size + retry gate + elevation branch) — nothing below that keeps
// all five guarantees (verified bytes, loud failure, right elevation
// with a recognizable prompt, visible outcome, quoteless encoding).
// Pure, tested.
//
// Elevation note: whoami group check (proven for months across all
// boxes; the .NET IsInRole shorthand failed type resolution on PS 5.1);
// the outer encode cap (4000) enforces the budget on every mint.
func buildInstallCMDMode(token, assetID string, size int64, mode string) string {
	fetch := fmt.Sprintf(`try{iwr -Headers @{Authorization='Bearer %s';Accept='application/octet-stream'} -Uri https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/%s -OutFile $o -TimeoutSec 600}catch{}`, token, assetID)
	if mode == "curl" {
		fetch = curlFetch(fmt.Sprintf(`'Authorization: Bearer %s'`, token), assetID)
	}
	parts := []string{
		`Write-Host '` + cmdMarker + `'`,
		`$o=($env:TEMP+'\A.exe')`,
	}
	return strings.Join(append(parts, installTail(fetch, fmt.Sprintf("%d", size))...), ";")
}

// buildInstallPS1 renders the installer as a file (install-agent.ps1)
// instead of a chat paste: secrets stay OUT (token/asset/size arrive
// via $env, length-checked so a damaged paste fails LOUD at the top
// instead of mid-script), the code itself travels over HTTPS byte-exact.
// exeID/exeSize are baked in as defaults (env overrides win), so the
// box-side bootstrap is three short lines. Always the curl full-retry
// fetcher (the paste path exists for healthy pipes). Pure, tested.
func buildInstallPS1(exeID string, exeSize int64) string {
	parts := []string{
		`Write-Host '` + ps1Marker + `'`,
		`$t=$env:RMM_TOKEN;$id=$env:RMM_ASSET;$size=[int64]$env:RMM_SIZE`,
		fmt.Sprintf(`if([string]::IsNullOrWhiteSpace($id)){$id='%s'};if($size -le 0){$size=%d}`, exeID, exeSize),
		`if([string]::IsNullOrWhiteSpace($t) -or $t.Length -lt 20){throw 'RMM_TOKEN missing or truncated (re-paste the set line)'}`,
		`$o=($env:TEMP+'\A.exe')`,
	}
	tail := installTail(curlFetch(`('Authorization: Bearer '+$t)`, "$id"), "$size")
	return strings.Join(append(parts, tail...), ";") + "\n"
}

// encodeCMD base64-encodes the one-liner for powershell -EncodedCommand
// (UTF-16LE, like the hand-rolled scripts it replaces). Refuses double
// quotes (they break the outer call shape), verifies the round-trip, and
// caps length. Pure, tested.
func encodeCMD(ps string) (string, error) {
	if strings.Contains(ps, `"`) {
		return "", fmt.Errorf("double quote leak")
	}
	u16 := utf16.Encode([]rune(ps))
	raw := make([]byte, 0, len(u16)*2)
	for _, v := range u16 {
		raw = append(raw, byte(v), byte(v>>8))
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	back, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(back) != string(raw) {
		return "", fmt.Errorf("round-trip mismatch")
	}
	if len(b64) > 4000 {
		return "", fmt.Errorf("cmd too long: %d", len(b64))
	}
	return "powershell -WindowStyle Hidden -EncodedCommand " + b64, nil
}
