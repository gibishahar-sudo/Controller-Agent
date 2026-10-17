<#
.SYNOPSIS
  Validate-Credential - prove ONE operator-supplied credential can perform
  the clone arm's exact path against a workgroup host.

.DESCRIPTION
  Single-credential validator. Takes a host plus a username/password the
  operator already holds (reset via physical access, owner-provided, or
  from records) and runs the full write-test:

    session hygiene -> map ADMIN$ with explicit creds -> canary write ->
    read-back compare -> DCOM Win32_Process.Create no-op -> delete canary
    -> session teardown.

  There is no candidate generation, no tier list, no attempt loop, no
  multi-host guessing in this file. One credential in, one verdict out.

  PowerShell 5.1, no external modules, no downloads. Password is carried
  as a SecureString and marshalled to unmanaged memory only for the
  WNetAddConnection2W call (never placed on a command line); the BSTR
  is zeroed immediately after use.

.PARAMETER Host
  Target IPv4/hostname, e.g. 192.168.68.51.

.PARAMETER User
  Username as the target expects it. For a workgroup LOCAL account use
  the HOST-qualified form, e.g. ".\Administrator" or "PCNAME\Admin".
  A bare name is passed through unchanged.

.PARAMETER Pass
  The password as a SecureString, e.g.:
    $s = Read-Host "Password" -AsSecureString

.OUTPUTS
  [bool] $true on a full pass, $false otherwise. Human-readable progress
  (including the failed stage name, and the two vault lines plus canary
  result on success) goes to the host so it never pollutes the return.

.EXAMPLE
  $s = Read-Host "Target password" -AsSecureString
  Validate-Credential -Host 192.168.68.51 -User ".\Administrator" -Pass $s
#>

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Mpr {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NETRESOURCE {
        public int dwScope;
        public int dwType;
        public int dwDisplayType;
        public int dwUsage;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpLocalName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpRemoteName;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpComment;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpProvider;
    }
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    public static extern int WNetAddConnection2W(
        ref NETRESOURCE lpNetResource,
        string lpPassword,
        string lpUsername,
        int dwFlags);
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    public static extern int WNetCancelConnection2W(
        string lpName,
        int dwFlags,
        bool fForce);
}
"@ | Out-Null

function Clear-HostSessions {
    param([string]$Target)
    # Remove every existing session to this host so stale state (incl.
    # error 1219 "multiple connections" poisoning) cannot skew the test.
    $listed = net use 2>$null | Select-String -Pattern ([regex]::Escape("\\" + $Target)) -AllMatches
    foreach ($m in $listed) {
        $share = ($m.Line -split '\s+') | Where-Object { $_ -like "\\$Target*" } | Select-Object -First 1
        if ($share) { net use $share /delete /y 2>$null | Out-Null }
    }
    # Belt and braces: drop any bare \\host connection record itself.
    net use "\\$Target" /delete /y 2>$null | Out-Null
    [void][Mpr]::WNetCancelConnection2W("\\$Target", 0, $true)
}

function Test-HostSessionGone {
    param([string]$Target)
    -not (net use 2>$null | Select-String -Pattern ([regex]::Escape("\\" + $Target)) -Quiet)
}

function Validate-Credential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Host,
        [Parameter(Mandatory = $true)][string]$User,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Pass
    )

    $adminRoot = "\\$Host\ADMIN$"
    $tempDir   = Join-Path $adminRoot "Temp"
    $canary    = "rmm-verify-$([guid]::NewGuid().ToString('N').Substring(0,12)).txt"
    $canaryAbs = Join-Path $tempDir $canary
    $canaryBody = "rmm-validate|$Host|$([datetime]::UtcNow.ToString('o'))|$([guid]::NewGuid())"

    $fail = { param($stage, $detail) Write-Host "RESULT: FAIL stage=$stage $detail"; return $false }.GetNewClosure()

    # 1. Session hygiene.
    Write-Host "STAGE: session-hygiene (clearing stale \\$Host sessions)"
    Clear-HostSessions -Target $Host

    # 2. Map ADMIN$ with explicit creds (password via SecureString -> BSTR
    #    in memory only; never on a command line). 1219 => table was
    #    poisoned: clear once more and retry exactly once.
    Write-Host "STAGE: auth (WNetAddConnection2W to $adminRoot as $User)"
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pass)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
        $nr = New-Object Mpr+NETRESOURCE
        $nr.dwScope = 0; $nr.dwType = 1; $nr.dwDisplayType = 0; $nr.dwUsage = 0
        $nr.lpLocalName = $null; $nr.lpRemoteName = $adminRoot
        $nr.lpComment = $null; $nr.lpProvider = $null
        $rc = [Mpr]::WNetAddConnection2W([ref]$nr, $plain, $User, 0)
        $plain = $null
        if ($rc -eq 1219) {
            Write-Host "STAGE: auth hit 1219 (poisoned table) - clearing, one retry"
            Clear-HostSessions -Target $Host
            $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
            $rc = [Mpr]::WNetAddConnection2W([ref]$nr, $plain2, $User, 0)
            $plain2 = $null
        }
        if ($rc -ne 0) {
            return (& $fail "auth" "WNet rc=$rc")
        }
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    Write-Host "STAGE: auth OK"

    try {
        # 3. Canary write - authenticated-but-not-admin must fail HERE.
        Write-Host "STAGE: write (canary -> $canaryAbs)"
        try {
            [System.IO.File]::WriteAllText($canaryAbs, $canaryBody)
        }
        catch {
            return (& $fail "write" "(authenticated but ADMIN$ not writable: $($_.Exception.Message))")
        }

        # 4. Read-back compare.
        Write-Host "STAGE: readback (read + byte-compare)"
        try {
            $back = [System.IO.File]::ReadAllText($canaryAbs)
        }
        catch {
            return (& $fail "readback" "canary unreadable: $($_.Exception.Message)")
        }
        if ($back -ne $canaryBody) {
            return (& $fail "readback" "content mismatch")
        }
        Write-Host "STAGE: readback OK (match)"

        # 5. WMI no-op over DCOM (Get-WmiObject uses DCOM by default;
        #    -Credential keeps the password off the command line).
        Write-Host "STAGE: wmi (Win32_Process.Create no-op over DCOM)"
        try {
            $cred = New-Object System.Management.Automation.PSCredential($User, $Pass)
            $procClass = Get-WmiObject -List Win32_Process `
                -ComputerName $Host -Credential $cred -ErrorAction Stop
            $wmi = $procClass.Create("cmd.exe /c exit 0")
            if ($null -eq $wmi -or $wmi.ReturnValue -ne 0) {
                return (& $fail "wmi" "Create returned $($wmi.ReturnValue)")
            }
        }
        catch {
            return (& $fail "wmi" "DCOM create failed: $($_.Exception.Message)")
        }
        Write-Host "STAGE: wmi OK (ReturnValue=0)"

        # 6. Delete canary + verify deletion.
        Write-Host "STAGE: cleanup (delete canary)"
        try {
            [System.IO.File]::Delete($canaryAbs)
            if (Test-Path -LiteralPath $canaryAbs) {
                return (& $fail "cleanup" "canary still present after delete")
            }
        }
        catch {
            return (& $fail "cleanup" "delete failed: $($_.Exception.Message)")
        }

        Write-Host "RESULT: PASS all stages (auth, write, readback, wmi, cleanup)"
        Write-Host "VAULT FILE (two lines for nms-wmi-cred):"
        Write-Host $User
        Write-Host "VAULT LINE 2: <the password you supplied>"
        Write-Host "CANARY: wrote $($canaryBody.Length) bytes, read-back match, WMI ReturnValue=0"
        return $true
    }
    finally {
        # 7. Teardown - always runs.
        Clear-HostSessions -Target $Host
        if (Test-HostSessionGone -Target $Host) {
            Write-Host "STAGE: teardown OK (no residual \\$Host session)"
        }
        else {
            Write-Host "STAGE: teardown WARNING (residual session - clear with: net use \\$Host /delete /y)"
        }
    }
}
