<#
.SYNOPSIS
    Builds the audit-only Ultron Filter pilot without installing a driver or changing host trust.
.DESCRIPTION
    Requires explicit Microsoft altitude-assignment evidence, WDK tools and a successful catalog.
    Signing uses an existing user-store certificate only; signatures and native exit codes are checked.
    An artifact is not a release approval. Native protocol, signing route and isolated VM gates remain pending.
.PARAMETER AssignedAltitude
    Microsoft-assigned FSFilter Anti-Virus altitude. The source INF is deliberately unassigned.
.PARAMETER AltitudeAssignmentEvidencePath
    Existing local assignment evidence. Its hash is recorded for manual verification, not treated as proof by its filename.
.PARAMETER SigningCertificateThumbprint
    Existing code-signing certificate in CurrentUser/My. No certificate is created or imported.
.PARAMETER SkipSign
    Explicitly produces an unsigned developer build, never an installable/release-approved package.
#>
[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")][string]$Configuration = "Release",
    [ValidateSet("x64")][string]$Platform = "x64",
    [string]$AssignedAltitude,
    [string]$AltitudeAssignmentEvidencePath,
    [string]$SigningCertificateThumbprint,
    [switch]$SkipSign,
    [switch]$SkipBuild,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Verify
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Install -or $Uninstall -or $Verify) {
    throw "Driver activation/servicing is not part of this build script. An independently approved isolated VM pilot is required."
}
if ($SkipBuild) { throw "Existing unverified driver binaries cannot be repackaged by skipping the build." }
if ($AssignedAltitude -notmatch '^32[0-9]{4}(\.[0-9]+)?$' -or
    $AssignedAltitude -match '^320500(\.|$)') {
    throw "A valid, independently verified Microsoft-assigned altitude is required. Avira's assigned altitude is not available to Ultron."
}
if ([string]::IsNullOrWhiteSpace($AltitudeAssignmentEvidencePath)) {
    throw "Provide altitude assignment evidence; numeric syntax is not evidence of assignment."
}
$assignmentEvidence = Get-Item -LiteralPath $AltitudeAssignmentEvidencePath
if ($assignmentEvidence.PSIsContainer -or $assignmentEvidence.Length -le 0 -or $assignmentEvidence.Length -gt 65536) {
    throw "Assignment evidence must be a nonempty file no larger than 64 KiB."
}

function Find-DriverTool {
    param([string]$Name)
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    $kitRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kitRoot) {
        foreach ($version in (Get-ChildItem -LiteralPath $kitRoot -Directory | Sort-Object Name -Descending)) {
            $candidate = Join-Path $version.FullName ("x64\" + $Name)
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    throw "Required driver tool is missing: $Name"
}

function Invoke-CheckedDriverTool {
    param([string]$Executable, [string[]]$ToolArguments)
    & $Executable @ToolArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Driver tool failed with exit code $LASTEXITCODE : $Executable"
    }
}

$msbuild = Get-Command msbuild.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$msbuildPath = if ($msbuild) { $msbuild.Source } else { $null }
if (-not $msbuildPath) {
    foreach ($edition in @("Enterprise", "Professional", "Community")) {
        $candidate = "C:\Program Files\Microsoft Visual Studio\2022\$edition\MSBuild\Current\Bin\amd64\MSBuild.exe"
        if (Test-Path -LiteralPath $candidate) { $msbuildPath = $candidate; break }
    }
}
if (-not $msbuildPath) { throw "MSBuild/WDK C++ toolchain is required; no partial success will be reported." }
$inf2catPath = Find-DriverTool "inf2cat.exe"
$signtoolPath = if (-not $SkipSign) { Find-DriverTool "signtool.exe" } else { $null }
if (-not $SkipSign) {
    if ($SigningCertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') {
        throw "Provide the thumbprint of an existing signing certificate; this script never creates or imports host trust."
    }
    $certificate = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $SigningCertificateThumbprint)
    if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le (Get-Date) -or $certificate.NotBefore -gt (Get-Date)) {
        throw "The existing signing certificate is expired, not yet valid, or has no private key."
    }
}

$driverDirectory = Join-Path $PSScriptRoot "AegisFilter"
$outputDirectory = Join-Path $PSScriptRoot ("bin\" + $Platform + "\" + $Configuration)
$projectPath = Join-Path $driverDirectory "AegisFilter.vcxproj"
$sourceInf = Get-Content -LiteralPath (Join-Path $driverDirectory "AegisFilter.inf") -Raw
if (($sourceInf | Select-String -Pattern '"UNASSIGNED"' -AllMatches).Matches.Count -ne 1) {
    throw "The source INF must remain an unassigned template; review unexpected source changes before packaging."
}
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
Invoke-CheckedDriverTool $msbuildPath @(
    $projectPath, "/p:Configuration=$Configuration", "/p:Platform=$Platform",
    "/p:OutDir=$outputDirectory\", "/t:Rebuild", "/m", "/warnAsError")
$sysPath = Join-Path $outputDirectory "AegisFilter.sys"
$catPath = Join-Path $outputDirectory "AegisFilter.cat"
if (-not (Test-Path -LiteralPath $sysPath)) { throw "Successful tool exit did not produce the expected driver binary." }
$packagedInf = $sourceInf.Replace('"UNASSIGNED"', ('"' + $AssignedAltitude + '"'))
[System.IO.File]::WriteAllText((Join-Path $outputDirectory "AegisFilter.inf"), $packagedInf)
Invoke-CheckedDriverTool $inf2catPath @("/driver:$outputDirectory", "/os:10_X64")
if (-not (Test-Path -LiteralPath $catPath)) { throw "Catalog generation did not produce AegisFilter.cat." }

if (-not $SkipSign) {
    foreach ($filePath in @($sysPath, $catPath)) {
        Invoke-CheckedDriverTool $signtoolPath @("sign", "/v", "/s", "My", "/sha1", $SigningCertificateThumbprint,
            "/fd", "SHA256", "/tr", "https://timestamp.digicert.com", "/td", "SHA256", $filePath)
        Invoke-CheckedDriverTool $signtoolPath @("verify", "/kp", "/all", "/v", $filePath)
    }
}
$artifactManifest = [ordered]@{
    NativeMode = "AuditOnly"
    ReleaseApproved = $false
    Altitude = $AssignedAltitude
    AssignmentEvidenceSha256 = (Get-FileHash -LiteralPath $assignmentEvidence.FullName -Algorithm SHA256).Hash
    AssignmentIndependentlyVerified = $false
    DriverSha256 = (Get-FileHash -LiteralPath $sysPath -Algorithm SHA256).Hash
    CatalogSha256 = (Get-FileHash -LiteralPath $catPath -Algorithm SHA256).Hash
    SigningRequested = (-not $SkipSign)
    CreatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
}
[System.IO.File]::WriteAllText((Join-Path $outputDirectory "pilot-artifact.json"), ($artifactManifest | ConvertTo-Json))
Write-Warning "Audit-only build produced. No driver was installed or loaded; assignment validation, native identity, signing route and VM gates are still required."
if ($SkipSign) { Write-Warning "Unsigned developer artifact: do not install or publish as a security release." }
