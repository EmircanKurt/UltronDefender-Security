<#
.SYNOPSIS
    Runs an explicit allowlist of inert preview regressions; never executes the main live/credential suite.
#>
[CmdletBinding()]
param([string]$ResultsDirectory = (Join-Path $PSScriptRoot '../artifacts/preview-tests'), [switch]$NoBuild)
$ErrorActionPreference = 'Stop'
$workspaceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$folderIdentityFilter = 'FullyQualifiedName~AegisPC.Review.Tests.FolderAllowanceIdentityReviewTests'
$discoveryFilter = 'FullyQualifiedName~AegisPC.Review.Tests.ScanDiscoveryCancellationReviewTests'
$filter = 'FullyQualifiedName~AegisPC.Review.Tests.BrowserDefenderReviewTests|FullyQualifiedName~AegisPC.Review.Tests.FindingPresentationSafetyReviewTests|FullyQualifiedName~AegisPC.Review.Tests.GuardianFreshnessSafetyReviewTests|FullyQualifiedName~AegisPC.Review.Tests.NetworkEnforcementReviewTests|FullyQualifiedName~AegisPC.Review.Tests.PassiveObservationLifecycleReviewTests|FullyQualifiedName~AegisPC.Review.Tests.ProtectionTargetReviewTests|FullyQualifiedName~AegisPC.Review.Tests.QuarantineBulkReceiptReviewTests|FullyQualifiedName~AegisPC.Review.Tests.RemoteWirelessReviewTests|FullyQualifiedName~AegisPC.Review.Tests.ScanScopeStorageSafetyReviewTests|FullyQualifiedName~AegisPC.Tests.BehaviorCorrelationReviewTests|FullyQualifiedName~AegisPC.Tests.BehaviorObservationSafetyTests|FullyQualifiedName~AegisPC.Tests.CachePolicyRevisionReviewTests|FullyQualifiedName~AegisPC.Tests.ClassicScanUiReviewTests|FullyQualifiedName~AegisPC.Tests.ClaudeCriticalReviewTests|FullyQualifiedName~AegisPC.Tests.DecisionEvidenceIntegrityTests|FullyQualifiedName~AegisPC.Tests.DetectionReviewFixTests|FullyQualifiedName~AegisPC.Tests.EmbeddedScanPageReviewTests|FullyQualifiedName~AegisPC.Tests.FileContentClassificationTests|FullyQualifiedName~AegisPC.Tests.FilePipelineCoverageTests|FullyQualifiedName~AegisPC.Tests.FlatRouteBenignPipelineReviewTests|FullyQualifiedName~AegisPC.Tests.FlatRouteScanReviewTests|FullyQualifiedName~AegisPC.Tests.GuardScanSafetyReviewTests|FullyQualifiedName~AegisPC.Tests.ImplicitLocalPathPolicyTests|FullyQualifiedName~AegisPC.Tests.InspectionContractReviewTests|FullyQualifiedName~AegisPC.Tests.IpcBoundaryReviewTests|FullyQualifiedName~AegisPC.Tests.PlainDashboardUiReviewTests|FullyQualifiedName~AegisPC.Tests.PlainProtectionPresentationReviewTests|FullyQualifiedName~AegisPC.Tests.ProtectionCommandLifecycleReviewTests|FullyQualifiedName~AegisPC.Tests.RealtimeRevisionAuditReviewTests|FullyQualifiedName~AegisPC.Tests.RealtimeWatcherRecoveryTests|FullyQualifiedName~AegisPC.Tests.ResourceCorrectnessReviewTests|FullyQualifiedName~AegisPC.Tests.ScanQueueFailureSafetyTests|FullyQualifiedName~AegisPC.Tests.ScanRouteUiReviewTests|FullyQualifiedName~AegisPC.Tests.ScoringRegressionTests|FullyQualifiedName~AegisPC.Tests.SilentScanPresentationReviewTests|FullyQualifiedName~AegisPC.Tests.TargetResolutionTests|FullyQualifiedName~AegisPC.Tests.UltronChiefSafetyTests|FullyQualifiedName~AegisPC.Review.Tests.AntiEvasionSearchPerformanceReviewTests|FullyQualifiedName~AegisPC.Tests.InstallerWorkflowTests|FullyQualifiedName~AegisPC.Tests.DeploymentScriptReviewTests'
$arguments = @('test', (Join-Path $workspaceRoot 'tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj'), '-c', 'Release', '-warnaserror', '--filter', $filter, '--logger', 'trx;LogFileName=benign-preview.trx', '--results-directory', $ResultsDirectory)
if ($NoBuild) { $arguments += '--no-build' }
$arguments[$arguments.IndexOf('--filter') + 1] += '|' + $folderIdentityFilter
$arguments[$arguments.IndexOf('--filter') + 1] += '|' + $discoveryFilter
& dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw "Selected benign regressions failed: $LASTEXITCODE" }
[xml]$result = Get-Content -LiteralPath (Join-Path $ResultsDirectory 'benign-preview.trx') -Raw
$counts = $result.TestRun.ResultSummary.Counters
if ([int]$counts.executed -lt 1 -or [int]$counts.failed -ne 0 -or [int]$counts.notExecuted -ne 0) { throw 'Missing, failed or skipped test results cannot certify this preview.' }
$counts | Select-Object total,executed,passed,failed,notExecuted
