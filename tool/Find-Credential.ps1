<#
.SYNOPSIS
  Find-Credential - work an ordered shortlist of candidate pairs against ONE
  workgroup host, validating each with Validate-Credential until one passes
  the full write-test (auth + canary write + readback + WMI no-op).

.DESCRIPTION
  Tiered shortlist, most-likely-first, hard cap -MaxAttempts (default 400):

    Tier 0  derived     hostname / NMS box / workgroup / -Hints words,
                        original + capitalized, bare and with 123, 1234, !,
                        year suffixes, plus leet variants of the bare word
    Tier 1  defaults     Windows default admin pairs (incl. blank password)
    Tier 2  human       common human passwords incl. <word>-based
    Tier 3  seasonal     Season / Season+year combinations
    Tier 4  keyboard    keyboard walks

  Leetspeak is applied to Tier 0 only (one full-substitution variant per
  word) so the tail stays bounded. Usernames: Administrator, admin, Admin,
  hostname-derived, -UserHints, user.

  Non-destructive: the only target write is the validator's canary, which it
  deletes itself. Resume log lives under -LogDir; re-runs skip previously
  attempted pairs unless -Fresh. -DryRun prints the ordered plan and total
  count without touching the target. Passwords are handed to the validator
  as SecureStrings and never appear on a command line.

  NOTE: the credential this finds is GLOBAL on the NMS box - the vault file
  (nms-wmi-cred) holds ONE pair for every host. Correct on a flat
  workgroup LAN (same admin everywhere); the first heterogeneous box will
  simply read no-hit against the shared pair. That is the design, not a bug.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string[]]$Hints = @(),          # evidence words: names, pets, company
    [string[]]$UserHints = @(),      # extra candidate usernames
    [string]$LogDir = (Join-Path $env:USERPROFILE '.rmm-guess'),
    [switch]$Fresh,                  # ignore resume log
    [switch]$DryRun,                # print plan only, touch nothing
    [int]$MaxAttempts = 400,       # hard cap
    [switch]$Json                  # machine contract: on success print exactly
                                    # one {"user":...,"pass":...} line on
                                    # stdout, nothing else; chatter is silenced
)

$sep = [char]1

# Say is the human channel: silenced in -Json mode so the ONLY stdout is the
# contract line. The NMS parses that line; it never scrapes human output.
function Say ([string]$m) { if (-not $Json) { Write-Host $m } }

# NOTE: $ErrorActionPreference deliberately NOT set to 'Stop' here - script
# scope leaks into the dot-sourced validator and would turn its non-terminating
# errors into terminating ones, letting a correct pair be swallowed as a miss.
# The call site uses -ErrorAction Continue as the guard instead.

# --- load the validator (must sit in the same folder) ---------------------
$validatorPath = Join-Path $PSScriptRoot 'Validate-Credential.ps1'
if (-not (Test-Path -LiteralPath $validatorPath)) {
    throw "Validate-Credential.ps1 not found next to this script ($PSScriptRoot)"
}
. $validatorPath

# --- helpers --------------------------------------------------------------
function Get-Cap ([string]$s) {
    if ($s.Length -gt 0) { $s.Substring(0,1).ToUpper() + $s.Substring(1).ToLower() } else { $s }
}
function Get-Leet ([string]$s) {
    $s.Replace('a','@').Replace('o','0').Replace('s','$').Replace('e','3').Replace('i','1')
}

# --- evidence words -------------------------------------------------------
# DNS reverse lookup usually has no PTR records on a workgroup LAN, but
# NetBIOS answers directly: nbtstat -A <ip> returns the TARGET's own
# computer name without any DNS. The <00> UNIQUE name is the single best
# Tier-0 word (hostname-based passwords), so it goes in FIRST.
$nbName = ''
try {
    $nbt = nbtstat -A $Target 2>$null
    if ($nbt) {
        foreach ($ln in @($nbt)) {
            if ($ln -match '^\s*(\S+)\s+<00>\s+UNIQUE') { $nbName = $Matches[1]; break }
        }
    }
} catch { }

$targetHost = ''
try { $targetHost = ([System.Net.Dns]::GetHostEntry($Target)).HostName.Split('.')[0] } catch { }

# The target's name however we learned it (NetBIOS preferred - it is the
# box's own name; the DNS answer, when present, agrees).
$boxName = if ($nbName) { $nbName } else { $targetHost }

$workgroup = ''
try { $workgroup = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Workgroup } catch { }

# Order matters: target evidence first (NetBIOS name, then DNS name), then
# the NMS box's own words, then operator hints. Exact duplicates drop;
# case variants deliberately survive (they are different guesses).
$words = New-Object System.Collections.Generic.List[string]
foreach ($w in @($nbName, $targetHost, $env:COMPUTERNAME, $workgroup) + $Hints) {
    if ($w -and $w.Trim()) { $words.Add($w.Trim()) }
}
$words = @($words | Select-Object -Unique)

# hostname-derived usernames: full host, plus token after - / . / digit
$hostDerived = New-Object System.Collections.Generic.List[string]
if ($boxName) {
    $hostDerived.Add($boxName)
    if ($boxName -match '^(.*?)[-.\d]+(.+)$' -and $Matches[2]) { $hostDerived.Add($Matches[2]) }
}

$thisYear = (Get-Date).Year
$years = @($thisYear, ($thisYear - 1), ($thisYear - 2))

# --- tier password lists ---------------------------------------------------
$tier0 = New-Object System.Collections.Generic.List[string]
foreach ($w in $words) {
    foreach ($base in @($w, (Get-Cap $w))) {
        foreach ($suf in (@('', '123', '1234', '!') + $years)) { $tier0.Add("$base$suf") }
    }
    $tier0.Add((Get-Leet $w))
    $tier0.Add((Get-Leet $w) + '123')
}
$tier0Users = (@($UserHints) + @($hostDerived) + @('Administrator')) | Where-Object { $_ } | Select-Object -Unique

$tier1DefaultPasses = @('password','Password1','P@ssw0rd','Welcome1','letmein','1234','12345','123456')
$tier1Users = @('Administrator','admin','Admin')

$tier2 = New-Object System.Collections.Generic.List[string]
foreach ($p in @('Password1','Passw0rd','Qwerty123','Welcome123','letmein1','Admin@123','Admin1234','admin123')) { $tier2.Add($p) }
foreach ($w in $words) {
    foreach ($suf in @('123','123!','@123')) { $tier2.Add("$w$suf") }
    foreach ($y in $years) { $tier2.Add("$w$y") }
}
$tier2Users = ($tier0Users + @('admin','user')) | Select-Object -Unique

$tier3 = New-Object System.Collections.Generic.List[string]
foreach ($season in @('Spring','Summer','Autumn','Winter')) {
    $tier3.Add($season)
    foreach ($y in $years) { $tier3.Add("$season$y") }
}
$tier3Users = @('Administrator','admin')

$tier4 = @('qwerty','qwerty123','1q2w3e4r','1qaz2wsx','asdf1234','zaq12wsx')
$tier4Users = @('Administrator','admin')

# --- ordered candidate list (dedup + hard cap) ------------------------------
$candidates = New-Object System.Collections.Generic.List[object]
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
function Add-Pair ([string]$tier, [string[]]$users, [string[]]$passes) {
    foreach ($u in $users) {
        foreach ($p in $passes) {
            $key = "$u$sep$p"
            if (-not $seen.Add($key)) { continue }
            if ($script:candidates.Count -ge $script:MaxAttempts) { return }
            $script:candidates.Add([pscustomobject]@{ Tier = $tier; User = $u; Pass = $p })
        }
    }
}
Add-Pair 't0-derived'   $tier0Users $tier0
Add-Pair 't1-defaults'   @('Administrator','admin') @('')      # blank first
Add-Pair 't1-defaults'   $tier1Users $tier1DefaultPasses
Add-Pair 't2-human'      $tier2Users $tier2
Add-Pair 't3-seasonal'   $tier3Users $tier3
Add-Pair 't4-keyboard'   $tier4Users $tier4

# --- resume log ------------------------------------------------------------
$tried = New-Object 'System.Collections.Generic.HashSet[string]'
if (-not $DryRun) {
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
    $logFile = Join-Path $LogDir ($Target + '.attempts.txt')
    if (-not $Fresh -and (Test-Path -LiteralPath $logFile)) {
        Get-Content -LiteralPath $logFile | ForEach-Object {
            if ($_ -like 'FOUND`t*') { return }     # never register the marker line as an attempt
            $parts = $_ -split "`t", 2
            if ($parts.Count -eq 2) { [void]$tried.Add($parts[0] + $sep + $parts[1]) }
        }
    }
}

# --- dry run: plan only -----------------------------------------------------
if ($DryRun) {
    $candidates | Format-Table Tier, User, Pass -AutoSize | Out-String -Width 200 | Write-Host
    $candidates | Group-Object Tier | ForEach-Object { Write-Host ("{0}: {1} attempts" -f $_.Name, $_.Count) }
    Write-Host ("TOTAL attempts: {0} (cap {1})" -f $candidates.Count, $MaxAttempts)
    return
}

# --- main loop: stop at first full pass --------------------------------------
$i = 0
foreach ($c in $candidates) {
    if ($tried.Contains($c.User + $sep + $c.Pass)) { continue }
    $i++
    $masked = if ($c.Pass.Length -gt 0) { '*' * $c.Pass.Length } else { '(blank)' }
    Say ("[{0}/{1}] tier={2} user={3} pass={4}" -f $i, $candidates.Count, $c.Tier, $c.User, $masked)

    # Explicit boolean verdict: capture the call's success stream as an array
    # and test membership of $true, so stray success-stream output can never
    # make a failed pair read as a hit.
    $ok = $false
    try {
        $sec = ConvertTo-SecureString $c.Pass -AsPlainText -Force
        $r = @(Validate-Credential -Host $Target -User $c.User -Pass $sec -ErrorAction Continue 6>$null)
        $ok = ($r -contains $true)
    } catch { $ok = $false }

    if ($ok) {
        Add-Content -LiteralPath $logFile -Value ("FOUND`t" + $c.User + "`t" + $c.Pass)
        if ($Json) {
            # The NMS contract: exactly one machine-readable line on stdout.
            # (Blank passwords are legal, so both keys are always emitted.)
            $line = [ordered]@{ user = $c.User; pass = $c.Pass } | ConvertTo-Json -Compress
            Write-Output $line
            return
        }
        Say "RESULT: PASS (auth + canary write + readback + WMI no-op + cleanup)"
        Say "VAULT FILE (two lines for nms-wmi-cred):"
        Say $c.User
        Say $c.Pass
        return
    }
    Add-Content -LiteralPath $logFile -Value ($c.User + "`t" + $c.Pass)
}
Say "RESULT: no candidate passed - see $logFile (re-run is safe; failed pairs are skipped)"
