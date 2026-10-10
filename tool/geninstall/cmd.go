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
	parts := []string{
		`$h=@{Authorization='Bearer ` + token + `'}`,
		`$u='https://api.github.com/repos/gibishahar-sudo/Controller-/releases/assets/` + assetID + `'`,
		`$o=($env:TEMP+'\A.exe')`,
		fmt.Sprintf(`$ok=$false;for($i=1;$i -le 3 -and !$ok;$i++){try{iwr -Headers ($h+@{Accept='application/octet-stream'}) -Uri $u -OutFile $o -TimeoutSec 600}catch{};if((Test-Path $o)-and((Get-Item $o).Length -eq %d)){$ok=$true}}`, size),
		`if(!$ok){throw 'download incomplete after 3 tries'}`,
		`$a=[bool]((whoami /groups)-match'S-1-16-12288')`,
		`if($a){$c=Start-Process $o '--silent' -Wait -PassThru -WindowStyle Hidden}else{$c=Start-Process $o '--silent' -Verb RunAs -Wait -PassThru -WindowStyle Hidden}`,
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
