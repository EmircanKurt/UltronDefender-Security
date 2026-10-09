<#
.SYNOPSIS
Read-only offline validation of a reviewed benign corpus and its paired VM measurement records.
.DESCRIPTION
Does not download, execute, extract, scan or upload files, clear OS caches, or change protection.
Manifest declarations are not independent proof of origin, license or measured hardware state.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CorpusRoot,
    [Parameter(Mandatory)][string]$CorpusManifest,
    [string]$MeasurementsManifest = ''
)
$ErrorActionPreference = 'Stop'
$corpusBase = [IO.Path]::GetFullPath($CorpusRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not (Test-Path -LiteralPath $corpusBase -PathType Container)) { throw 'Corpus root does not exist.' }
$manifest = Get-Content -LiteralPath $CorpusManifest -Raw | ConvertFrom-Json
$families = @('NativeProxy','Overlay','ManagedPlugin','JarMod','PackedBenignPe','InstallerScript')
$files = @($manifest.Files)
if ($files.Count -lt 30) { throw 'Gate pending: at least 30 unique reviewed benign files are required.' }
$verifiedHashes = @()
foreach ($file in $files) {
    if ($file.Family -notin $families) { throw 'Unknown corpus family.' }
    if ($file.OriginReviewed -isnot [bool] -or -not $file.OriginReviewed -or $file.Holdout -isnot [bool] -or
        -not $file.Version -or -not $file.License -or -not $file.LicenseReference -or
        -not $file.ReviewedAtUtc -or $file.SourceKind -ne 'OfficialBenignBinary') { throw 'Unreviewed origin/version/license metadata.' }
    foreach ($reference in @($file.SourceReference, $file.LicenseReference)) {
        $uri = [Uri]$reference
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https') { throw 'An official HTTPS reference is required.' }
    }
    $path = [IO.Path]::GetFullPath((Join-Path $corpusBase $file.Path))
    if (-not $path.StartsWith($corpusBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Corpus member escapes root.' }
    $member = Get-Item -LiteralPath $path
    if ($member -isnot [IO.FileInfo] -or ($member.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'A regular corpus file is required.' }
    $parent = $member.Directory
    while ($parent -and ($parent.FullName -eq $corpusBase -or
        $parent.FullName.StartsWith($corpusBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) {
        if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Corpus reparse paths are not eligible.' }
        $parent = $parent.Parent
    }
    $sourcePath = [IO.Path]::GetFullPath((Join-Path $corpusBase $file.Path))
    $source = [IO.File]::Open($sourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($algorithm.ComputeHash($source)).Replace('-','') }
    finally { $source.Dispose(); $algorithm.Dispose() }
    if ($file.SHA256 -notmatch '^[A-Fa-f0-9]{64}$' -or $hash -ne $file.SHA256) { throw 'Corpus SHA-256 mismatch.' }
    $verifiedHashes += $hash
}
if (@($verifiedHashes | Sort-Object -Unique).Count -ne $files.Count) { throw 'Duplicate payloads cannot inflate the corpus.' }
if (@($files.Family | Sort-Object -Unique).Count -ne 6) { throw 'All six families are required.' }
$holdouts = @($files | Where-Object Holdout | Select-Object -ExpandProperty Family -Unique)
if ($holdouts.Count -ne 1 -or @($files | Where-Object { $_.Family -eq $holdouts[0] -and -not $_.Holdout }).Count -ne 0) { throw 'Exactly one entire family must be held out.' }
$algorithm = [Security.Cryptography.SHA256]::Create()
try { $fingerprint = [BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes(($verifiedHashes | Sort-Object) -join "`n"))).Replace('-','') }
finally { $algorithm.Dispose() }
if (-not $MeasurementsManifest) { [pscustomobject]@{CorpusCount=$files.Count;CorpusFingerprint=$fingerprint;PerformanceGate='Pending';OriginLicense='Human declarations, not certified'}; return }
$measurements = Get-Content -LiteralPath $MeasurementsManifest -Raw | ConvertFrom-Json
if (@($measurements.Runs).Count -ne 20) { throw 'Exactly twenty paired baseline/candidate records are required.' }
function Median($values) { $ordered = @($values | Sort-Object); if ($ordered.Count -ne 5) { throw 'Exactly five repetitions per mode/build are required.' }; return [double]$ordered[2] }
$summaries = foreach ($build in @('Baseline','Candidate')) {
    foreach ($mode in @('Cold','Warm')) {
        $rows = @($measurements.Runs | Where-Object { $_.Build -eq $build -and $_.Mode -eq $mode })
        if ($rows.Count -ne 5 -or @($rows.Repetition | Sort-Object -Unique).Count -ne 5) { throw 'Missing or duplicate repetitions.' }
        foreach ($row in $rows) {
            if ($row.CorpusFingerprint -ne $fingerprint -or $row.Files -ne $files.Count -or -not $row.MachineFingerprint -or -not $row.ScopeFingerprint -or
                $row.WallMs -le 0 -or $row.PeakWorkingSetBytes -le 0 -or $null -eq $row.ProcessCpuPercent -or
                $row.ProcessCpuPercent -lt 0 -or $row.ProcessCpuPercent -gt 100 -or $null -eq $row.QueueP95Ms -or $row.QueueP95Ms -lt 0 -or
                $null -eq $row.CoverageLossCount -or $row.CoverageLossCount -lt 0) { throw 'Incomplete or mismatched measurements.' }
            if ($mode -eq 'Cold' -and $row.ColdBasis -notin @('VmReboot','VerifiedCacheReset')) { throw 'Process restart is not a cold disk-cache measurement.' }
        }
        [pscustomobject]@{Build=$build;Mode=$mode;MedianMs=(Median $rows.WallMs);PeakBytes=($rows.PeakWorkingSetBytes | Measure-Object -Maximum).Maximum;CoverageLoss=($rows.CoverageLossCount | Measure-Object -Maximum).Maximum}
    }
}
if (@($measurements.Runs.MachineFingerprint | Sort-Object -Unique).Count -ne 1 -or @($measurements.Runs.ScopeFingerprint | Sort-Object -Unique).Count -ne 1) { throw 'Machine/scope mismatch.' }
foreach ($mode in @('Cold','Warm')) {
    $baseline = $summaries | Where-Object { $_.Build -eq 'Baseline' -and $_.Mode -eq $mode }
    $candidate = $summaries | Where-Object { $_.Build -eq 'Candidate' -and $_.Mode -eq $mode }
    if ($candidate.MedianMs -gt $baseline.MedianMs * 1.10 -or $candidate.PeakBytes -gt $baseline.PeakBytes * 1.15 -or $candidate.CoverageLoss -gt $baseline.CoverageLoss) { throw 'Publication gate: performance/coverage regression requires investigation.' }
}
$summaries
