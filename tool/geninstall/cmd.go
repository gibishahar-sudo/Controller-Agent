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
// Elevation is explicit (v1.47.3 follow-up: a non-admin shell used to
// sail into RunAs with zero messaging, so "wasn't admin" was
// undiscoverable): .NET role check up front, loud notice, denial caught.
// Templates stay lean: headers/URL inline, abbreviated params (-Wa -Pa
// -Win), gi -ea instead of Test-Path. Floor is ~500 raw chars (token +
// URL + size + retry gate + elevation branch) — nothing below that keeps
// all four guarantees (verified bytes, loud failure, right elevation,
// visible outcome).
// Pure, tested.
//
// Elevation note: IsInRole(544) is WindowsBuiltInRole.Administrator as
// its stable SID suffix (saves ~100 chars over the full type name);
// the outer encode cap (4000) enforces the budget on every mint.
func buildInstallCMDMode(token, assetID string, size int64, mode string) string {
	fetch := fmt.Sprintf(`try{iwr -Headers @{Authorization='Bearer %s';Accept='application/octet-stream'} -Uri https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/%s -OutFile $o -TimeoutSec 600}catch{}`, token, assetID)
	if mode == "curl" {
		fetch = fmt.Sprintf(`& curl.exe -sS -L -C - --retry 2 --retry-all-errors --max-time 240 -H 'Authorization: Bearer %s' -H 'Accept: application/octet-stream' -o $o https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/%s`, token, assetID)
	}
	parts := []string{
		`$o=$env:TEMP\A.exe`,
		fmt.Sprintf(`$ok=$false;for($i=0;$i -lt 3 -and !$ok;$i++){%s;if((gi $o -ea 0).Length -eq %d){$ok=$true}}`, fetch, size),
		`if(!$ok){throw 'download incomplete'}`,
		`$a=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(544);if(!$a){Write-Host 'not admin - approve the UAC prompt'}`,
		`if($a){$c=Start-Process $o --silent -Wa -Pa -Win Hidden}else{try{$c=Start-Process $o --silent -Verb RunAs -Wa -Pa -Win Hidden}catch{throw 'UAC declined or unavailable - run from an elevated prompt'}}`,
		`'a='+$a+' e='+$c.ExitCode`,
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
