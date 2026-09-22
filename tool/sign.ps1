# Signs release exes with the local RMM code-signing cert.
# The PFX never enters the repo: it lives at Documents\RMM-signing and the
# password comes from the user env var RMM_SIGN_PWD (set at cert creation).
# Usage: .\tool\sign.ps1 "Agent-Setup.exe,MicrosoftWindowsClient.exe,..."
# (single comma-separated arg: some launchers drop extra argv entries).
param([string]$FileList)
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($FileList)) {
  Write-Host 'Usage: .\tool\sign.ps1 "a.exe,b.exe,..."'
  exit 2
}
$pwdPlain = $env:RMM_SIGN_PWD
if ([string]::IsNullOrWhiteSpace($pwdPlain)) {
  # Child processes can inherit a stale env block; read the registry directly.
  $pwdPlain = [Environment]::GetEnvironmentVariable("RMM_SIGN_PWD", "User")
}
if ([string]::IsNullOrWhiteSpace($pwdPlain)) {
  Write-Host "RMM_SIGN_PWD is not set (user env). Cannot sign."
  exit 2
}
$cands = @()
if ($env:RMM_SIGN_PFX) { $cands += $env:RMM_SIGN_PFX }
$cands += Join-Path ([Environment]::GetFolderPath("MyDocuments")) "RMM-signing\RMM-sign.pfx"
$cands += Join-Path (Join-Path $env:USERPROFILE "Documents") "RMM-signing\RMM-sign.pfx"
$pfx = $cands | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $pfx) {
  Write-Host ("Missing PFX. Tried: " + ($cands -join ", "))
  Write-Host "Set RMM_SIGN_PFX to its full path to override."
  exit 2
}
Write-Host ("PFX: " + $pfx)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, $pwdPlain)
Write-Host ("Signing with: " + $cert.Subject + " exp " + $cert.NotAfter.ToString("yyyy-MM-dd"))
$Files = @($FileList -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$failed = 0
Write-Host ("Files to sign: " + $Files.Count)
foreach ($f in $Files) {
  if (-not (Test-Path $f)) { Write-Host "SKIP (missing): $f"; $failed++; continue }
  try {
    $r = Set-AuthenticodeSignature -FilePath $f -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -HashAlgorithm SHA256
    $st = (Get-AuthenticodeSignature -FilePath $f).Status
    Write-Host ("{0}: sign={1} verify={2}" -f $f, $r.Status, $st)
    if ($st -ne "Valid") { $failed++ }
  } catch {
    Write-Host ("FAIL {0}: {1}" -f $f, $_.Exception.Message)
    $failed++
  }
}
exit $failed
