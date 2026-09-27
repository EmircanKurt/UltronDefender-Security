<#!
.SYNOPSIS
Runs the inert phase-two trust tests and rejects empty or unsuccessful test runs.
.DESCRIPTION
Requires restored packages. Does not change antivirus settings or load the live intervention test suite.
!#>
param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Release')

$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$testProject = Join-Path $taskRoot 'tests/AegisPC.Trust.Tests/AegisPC.Trust.Tests.csproj'
$resultDirectory = Join-Path $taskRoot ('tests/AegisPC.Trust.Tests/TestResults/checked-' + [Guid]::NewGuid().ToString('N'))
& dotnet test $testProject -c $Configuration --no-restore --results-directory $resultDirectory --logger 'trx;LogFileName=trust.trx'
if ($LASTEXITCODE -ne 0) { throw "Trust test runner failed with exit code $LASTEXITCODE." }
$reportPath = Join-Path $resultDirectory 'trust.trx'
if (-not (Test-Path -LiteralPath $reportPath)) { throw 'Test runner produced no TRX report.' }
[xml]$report = Get-Content -LiteralPath $reportPath -Raw
$counts = $report.TestRun.ResultSummary.Counters
if ($null -eq $counts -or [int]$counts.executed -lt 1 -or [int]$counts.failed -ne 0 -or
    [int]$counts.passed -ne [int]$counts.total) {
    throw "Trust tests were empty, skipped or unsuccessful. Inspect $reportPath"
}
Write-Host "Verified $($counts.passed) passing trust tests. Report: $reportPath"
