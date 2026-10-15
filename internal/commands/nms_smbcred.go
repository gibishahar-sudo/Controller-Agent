package commands

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Session-managed SMB for the vault-credential fallback (v1.49.23+).
//
// One mechanism, agreed by both sides: a PowerShell child reads the vault
// cred file into a PSCredential and opens a NON-PERSISTED PSDrive session.
// The drive is authentication only — every byte then moves over plain UNC
// paths, which both Go (os.WriteFile) and PowerShell agree on. New-PSDrive
// without -Persist is provider-scoped (invisible to .NET/Go), so the drive
// letter itself is never used for I/O; Remove-PSDrive is cosmetic only.
// The real teardown is enumerated `net use \\host\* /delete`.
//
// Non-persisted mappings live in our logon session, not in the PS child,
// so they survive its exit and cover Go UNC reads/writes (copy, verify)
// until teardown. Each clone job brackets setup/teardown; no cross-job
// session reuse, ever.

// parseNetUseShares extracts share paths (\\host\share) from `net use`
// output. Pure, tested (OK lines, disconnected/ghost entries, header,
// footer, and localized-ish noise all tolerated: only backslash-led
// tokens qualify).
func parseNetUseShares(output string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		for _, tok := range strings.Fields(line) {
			if len(tok) < 3 || tok[0] != '\\' || tok[1] != '\\' {
				continue
			}
			tok = strings.TrimRight(tok, " \t\r")
			if seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

// hostShares filters share paths to one host (case-insensitive \\host\...).
// Pure, tested.
func hostShares(shares []string, host string) []string {
	var out []string
	prefix := `\\` + strings.ToLower(host) + `\`
	for _, s := range shares {
		if strings.HasPrefix(strings.ToLower(s), prefix) {
			out = append(out, s)
		}
	}
	return out
}

// nmsNetUse runs `net use` hidden and returns raw output. Var for tests.
var nmsNetUse = func() (string, error) {
	out, err := runWithTimeout(30*time.Second, "net", "use")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// nmsNetUseDelete drops one share mapping. Var for tests.
var nmsNetUseDelete = func(share string) error {
	_, err := runWithTimeout(30*time.Second, "net", "use", share, "/delete", "/y")
	return err
}

// clearHostSessions deletes EVERY mapping for host (not just IPC$: 1219
// fires on any pre-existing connection to that server, including ghosts).
// Returns deleted count. Best-effort per entry: one stubborn mapping must
// not block the rest.
func clearHostSessions(host string) int {
	raw, err := nmsNetUse()
	if err != nil {
		return 0
	}
	n := 0
	for _, s := range hostShares(parseNetUseShares(raw), host) {
		if nmsNetUseDelete(s) == nil {
			n++
		}
	}
	return n
}

// smbSessionScript builds the establish script: vault cred file ->
// PSCredential -> New-PSDrive (auth only) -> SESSION-OK marker. The
// password travels file->PS memory only; the command carries the cred
// FILE path (already the established pattern), never the secret. Pure,
// tested (structure + no-secret assertions).
func smbSessionScript(host string) string {
	return `$cf=Get-Content -LiteralPath '` + strings.ReplaceAll(NMSCredPath(), "'", "''") + `';` +
		`$u=$cf[0].Trim();$p=$cf[1].TrimEnd("` + "`r,`n" + `");` +
		`$sec=ConvertTo-SecureString $p -AsPlainText -Force;` +
		`$cred=New-Object PSCredential($u,$sec);` +
		`try{New-PSDrive -Name RMMCLONE -PSProvider FileSystem -Root '\\` + strings.ReplaceAll(host, "'", "''") + `\ADMIN$' -Credential $cred -ErrorAction Stop | Out-Null;'SESSION-OK'}catch{'SESSION-FAIL: '+$_.Exception.Message}`
}

// smbSessionEstablish authenticates as the vault identity (full clear
// first, so 1219 can never fire on our own stale entries). Var for tests.
var smbSessionEstablish = func(host string) error {
	clearHostSessions(host)
	out, err := runWithTimeout(60*time.Second, "powershell", "-NoProfile", "-Command", smbSessionScript(host))
	if err != nil {
		return fmt.Errorf("session establish: %v", err)
	}
	if !strings.Contains(string(out), "SESSION-OK") {
		return fmt.Errorf("session establish refused: %s", classifyPSNetErr(strings.TrimSpace(string(out))))
	}
	return nil
}

// smbSessionTeardown drops every mapping for host (the real teardown;
// Remove-PSDrive is runspace-scoped and cannot do this cross-process).
var smbSessionTeardown = func(host string) {
	clearHostSessions(host)
}

// classifyPSNetErr maps PowerShell/.NET network errors to the same words
// as classifySMBErr (one table, two feeders). Pure, tested.
func classifyPSNetErr(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "access is denied") || strings.Contains(l, "0x80070005") || strings.Contains(l, "unauthorized"):
		return "access denied (account rejected — check vault user/password and target Administrators)"
	case strings.Contains(l, "network path was not found") || strings.Contains(l, "0x80070035"):
		return "bad network path (no route or SMB disabled on target)"
	case strings.Contains(l, "1219") || strings.Contains(l, "multiple connections"):
		return "multiple IPC$ sessions (full clear ran — retry once, else net use * /delete manually)"
	case strings.Contains(l, "53 ") || strings.Contains(l, "could not be found"):
		return "bad network path (no route or SMB disabled on target)"
	case strings.Contains(l, "timed out") || strings.Contains(l, "timeout"):
		return "stalled (link down mid-transfer?)"
	case s == "" || s == "SESSION-FAIL: ":
		return "session failed with no detail"
	default:
		return strings.TrimSpace(s)
	}
}

// --- per-host identity memory: which mechanism won (context|vault). ---
// Both legs (SMB + WMI) read the same record, so a clone can never split
// identities mid-flight. In-memory only (a reboot re-probes honestly).

var hostIdentMu sync.Mutex
var hostIdent = map[string]string{}

// recallHostIdentity returns the winning mechanism for host ("", context, vault).
func recallHostIdentity(host string) string {
	hostIdentMu.Lock()
	defer hostIdentMu.Unlock()
	return hostIdent[strings.ToLower(host)]
}

// recordHostIdentity pins the winning mechanism for host.
func recordHostIdentity(host, mech string) {
	hostIdentMu.Lock()
	defer hostIdentMu.Unlock()
	hostIdent[strings.ToLower(host)] = mech
}

// forgetHostIdentity drops the pin (cred file vanished, explicit reset).
func forgetHostIdentity(host string) {
	hostIdentMu.Lock()
	defer hostIdentMu.Unlock()
	delete(hostIdent, strings.ToLower(host))
}

// cimCreateCredScript builds the vault-credential remote-create script:
// same DCOM shape as cimCreateScript, PSCredential from the vault file.
// Pure, tested (DCOM + session + credential wiring, no secret).
func cimCreateCredScript(host, commandLine string) string {
	h := strings.ReplaceAll(host, "'", "''")
	cl := strings.ReplaceAll(commandLine, "'", "''")
	return `$cf=Get-Content -LiteralPath '` + strings.ReplaceAll(NMSCredPath(), "'", "''") + `';` +
		`$u=$cf[0].Trim();$p=$cf[1].TrimEnd("` + "`r,`n" + `");` +
		`$sec=ConvertTo-SecureString $p -AsPlainText -Force;` +
		`$cred=New-Object PSCredential($u,$sec);` +
		cimSessionPrelude(h, "-Credential $cred -ErrorAction Stop") + `;try{` +
		`Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='` + cl + `'} | Select-Object -ExpandProperty ReturnValue` +
		`}finally{Remove-CimSession -CimSession $s -ErrorAction SilentlyContinue}`
}

// nmsRemoteCreateCred runs a command line on host via WMI under the vault
// identity. Var so tests record instead of touching the LAN.
var nmsRemoteCreateCred = func(host, commandLine string) error {
	out, err := runWithTimeout(60*time.Second, "powershell", "-NoProfile", "-Command", cimCreateCredScript(host, commandLine))
	if err != nil {
		return err
	}
	if code := strings.TrimSpace(string(out)); code != "0" {
		return fmt.Errorf("remote create: %s", wmiReturnText(code))
	}
	return nil
}
