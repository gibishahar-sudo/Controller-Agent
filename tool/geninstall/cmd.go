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

// buildInstallCMDMode renders the one-liner with a selectable fetcher:
// "iwr" (Invoke-WebRequest, simple) or "curl" (curl.exe -C - resume +
// retries: survives pipes that RST mid-download, v1.47.3 HOME box).
// Elevation is explicit: .NET role check up front; non-admin relaunches
// POWERSHELL elevated (never the payload directly, so the UAC prompt
// names a familiar publisher) and reports the child's exit code; denial
// throws loudly. The triple-quote join keeps the whole template free of
// double quotes (the outer -EncodedCommand shape forbids them).
// Templates stay lean: headers/URL inline, abbreviated params (-Wa -Pa
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
		fetch = fmt.Sprintf(`& curl.exe -sS -L -C - --retry 2 --retry-all-errors --max-time 240 -H 'Authorization: Bearer %s' -H 'Accept: application/octet-stream' -o $o https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/%s`, token, assetID)
	}
	parts := []string{
		`$o=($env:TEMP+'\A.exe')`,
		fmt.Sprintf(`$ok=$false;for($i=0;$i -lt 3 -and !$ok;$i++){%s;if((gi $o -ea 0).Length -eq %d){$ok=$true}}`, fetch, size),
		`if(!$ok){throw 'download incomplete'}`,
		`$a=[bool](whoami /groups -match'S-1-16-12288')`,
		`if($a){$c=Start-Process $o --silent -Wa -Pa -Win Hidden;'a='+$a+' e='+$c.ExitCode}else{Write-Host 'not admin - approve the UAC prompt to continue';$exe=(Get-Item $o).FullName;try{$p=Start-Process powershell -Verb RunAs -ArgumentList ('-WindowStyle Hidden -NoProfile -Command & {$c=Start-Process '''+$exe+''' --silent -Wa -Pa -Win Hidden; exit $c.ExitCode}') -Wa -Pas}catch{throw 'UAC declined or unavailable - run from an elevated prompt'};'elevated installer exit='+$p.ExitCode}`,
	}
	return strings.Join(parts, ";")
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
