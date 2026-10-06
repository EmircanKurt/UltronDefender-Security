using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

[Collection("SequentialDiskTests")]
public sealed class FinalReviewScanRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Aegis_FinalReview_" + Guid.NewGuid().ToString("N"));
    public FinalReviewScanRegressionTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("notes.txt")]
    [InlineData("config.json")]
    [InlineData("report.docx")]
    [InlineData("payload.unknown")]
    [InlineData("file_ultron_canary.txt")]
    public void FilenameCannotOptOutOfDetection(string name)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, "BENIGN FILTER REVIEW FIXTURE");
        Assert.True(ScanFilterPolicy.IsInspectableCandidate(path));
        Assert.False(ScanFilterPolicy.IsSelfOwnedPath(path));
    }

    [Fact]
    public async Task FullEnumeration_DoesNotHideUserFoldersNamedLikeSystemFolders()
    {
        string directory = Path.Combine(_root, "Installer");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "benign.dat");
        File.WriteAllText(path, "BENIGN FIXTURE");
        var files = new System.Collections.Generic.List<string>();
        await new DirectoryWalker().EnumerateDirectorySafelyAsync(_root, true,
            file => { files.Add(file); return Task.CompletedTask; }, CancellationToken.None);
        Assert.Contains(path, files);
    }

    [Fact]
    public async Task ExpectedHashMismatch_PreservesSourceAndCreatesNoVaultRecord()
    {
        string path = Path.Combine(_root, "benign.txt");
        File.WriteAllText(path, "REPLACEMENT BENIGN CONTENT");
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Path.Combine(_root, "Vault"));
        var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
        {
            TargetFilePath = path, ForceKillHoldingProcesses = false,
            ExpectedSha256 = Convert.ToHexString(SHA256.HashData(new byte[] { 1, 2, 3 }))
        });
        Assert.False(result.Success);
        Assert.Equal("REPLACEMENT BENIGN CONTENT", File.ReadAllText(path));
        Assert.Empty(await engine.GetQuarantinedItemsAsync());
        Assert.Empty(Directory.GetFiles(engine.VaultDirectory, "*.quar*"));
    }

    [Fact]
    public async Task ConcurrentStarts_NotifyOnceAndReturnSameTask()
    {
        var scanner = new ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int notifications = 0;
        coordinator.ScanSessionStarted += _ => Interlocked.Increment(ref notifications);
        var tasks = Enumerable.Range(0, 24).Select(_ => Task.Run(() =>
            coordinator.StartScanAsync(ScanType.Custom, _root))).ToArray();
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(100);
        scanner.Complete.TrySetResult(true);
        await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, scanner.StartCount);
        Assert.Equal(1, notifications);
    }

    internal sealed class ControlledScanner : IFileScanner
    {
        public readonly TaskCompletionSource<bool> Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<bool> Complete = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int StartCount;
        public ScanResult Result { get; set; } = new() { Status = ScanStatus.Completed };
        public bool IsPaused { get; private set; }
        public void PauseScan() => IsPaused = true;
        public void ResumeScan() => IsPaused = false;
        public Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default) => Task.FromResult<SecurityFinding?>(null);
        public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout, CancellationToken cancellationToken = default)
            => Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero));
        public async Task<ScanResult> ScanDirectoryAsync(string path, ScanType scanType, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref StartCount);
            Started.TrySetResult(true);
            await Complete.Task.WaitAsync(cancellationToken);
            Result.ScanType = scanType;
            return Result;
        }
    }

    [Fact]
    public async Task ContentScanner_InspectsTailAndChunkBoundary()
    {
        string path = Path.Combine(_root, "benign.bin");
        var bytes = new byte[600000];
        System.Text.Encoding.ASCII.GetBytes("GetAsyncKeyState").CopyTo(bytes, 256 * 1024 - 5);
        System.Text.Encoding.ASCII.GetBytes("WriteProcessMemory").CopyTo(bytes, 550000);
        await File.WriteAllBytesAsync(path, bytes);
        var (_, apis) = await MalwareSignatureDatabase.CheckFileContentAndApisAsync(path);
        Assert.Contains(apis, a => a.ApiName == "GetAsyncKeyState");
        Assert.Contains(apis, a => a.ApiName == "WriteProcessMemory");
    }

    [Fact]
    public async Task ContentScanner_CancellationIsNotACleanResult()
    {
        string path = Path.Combine(_root, "benign.bin");
        File.WriteAllText(path, "BENIGN CONTENT");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MalwareSignatureDatabase.CheckFileContentAndApisAsync(path, cts.Token));
    }

    [Fact]
    public async Task GenericCommandText_IsNotAbsoluteMalwareEvidence()
    {
        string path = Path.Combine(_root, "benign.ps1");
        File.WriteAllText(path, "# Educational reference: amsiInitFailed");
        var plugin = new AegisPC.Security.Detection.Detectors.HashSignatureDetector(new HashService());
        var evidence = await plugin.EvaluateAsync(new AegisPC.Contracts.Detection.DetectionContext { FilePath = path });
        Assert.NotEmpty(evidence);
        Assert.DoesNotContain(evidence, e => e.Confidence == AegisPC.Contracts.Detection.EvidenceConfidence.Absolute && e.ScoreContribution > 0);
    }

    [Theory]
    [InlineData("container.docx")]
    [InlineData("container.jpg")]
    public async Task ArchiveMemberFilenameAndOuterExtensionCannotHideContent(string name)
    {
        string path = Path.Combine(_root, name);
        using (var archive = System.IO.Compression.ZipFile.Open(path, System.IO.Compression.ZipArchiveMode.Create))
        using (var output = new StreamWriter(archive.CreateEntry("notes.txt").Open()))
        {
            await output.WriteAsync(new string(' ', 300000));
            await output.WriteAsync("Educational reference: amsiInitFailed");
        }
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        Assert.True(result.IsArchive);
        Assert.True(result.IsComplete);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(FindingCategory.SuspiciousScript, finding.Category);
        Assert.NotEqual(RiskLevel.ConfirmedMalicious, finding.RiskLevel);
    }

    [Fact]
    public async Task BackgroundClaimCannotChangeManualScanOrCancelItsSession()
    {
        var scanner = new ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var manual = coordinator.StartScanAsync(ScanType.Custom, _root);
        var session = coordinator.CurrentSession!;
        bool changed = false;
        using var backgroundToken = new CancellationTokenSource();
        var background = await coordinator.TryStartBackgroundScanAsync(ScanType.Quick, backgroundToken.Token, () => changed = true);
        backgroundToken.Cancel();
        Assert.Null(background);
        Assert.False(changed);
        Assert.False(session.CancellationToken.IsCancellationRequested);
        scanner.Complete.TrySetResult(true);
        await manual;
    }

    [Fact]
    public async Task OwnedBackgroundCancellationStopsOnlyItsScan()
    {
        var scanner = new ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        using var backgroundToken = new CancellationTokenSource();
        var background = coordinator.TryStartBackgroundScanAsync(ScanType.Quick, backgroundToken.Token);
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        backgroundToken.Cancel();
        var result = await background.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ScanStatus.Cancelled, result!.Status);
        Assert.Null(coordinator.CurrentSession);
    }

    [Fact]
    public async Task RenamedNestedZip_IsPartialRatherThanCleanCoverage()
    {
        using var inner = new MemoryStream();
        using (var archive = new System.IO.Compression.ZipArchive(inner, System.IO.Compression.ZipArchiveMode.Create, true))
        using (var writer = new StreamWriter(archive.CreateEntry("benign.txt").Open()))
            await writer.WriteAsync("BENIGN NESTED FIXTURE");
        string path = Path.Combine(_root, "outer.zip");
        using (var archive = System.IO.Compression.ZipFile.Open(path, System.IO.Compression.ZipArchiveMode.Create))
        using (var output = archive.CreateEntry("inner.txt").Open())
            await output.WriteAsync(inner.ToArray());
        var result = await new ArchiveSafetyScanner().ScanArchiveAsync(path);
        Assert.False(result.IsComplete);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task CancellationDuringPolicy_DoesNotReportCompletedOrLoseFindings()
    {
        var finding = new SecurityFinding { ObjectPath = "inert fixture", RiskScore = 65 };
        var scanner = new ControlledScanner { Result = new ScanResult { Status = ScanStatus.Completed,
            ScannedFiles = 1, Findings = new() { finding } } };
        var policy = new WaitingPolicy();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService(), policyEngine: policy);
        var task = coordinator.StartScanAsync(ScanType.Custom, _root);
        scanner.Complete.TrySetResult(true);
        await policy.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        coordinator.CancelScan();
        var result = await task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ScanStatus.Cancelled, result!.Status);
        Assert.Equal(ScanState.Cancelled, coordinator.State);
        Assert.Same(finding, Assert.Single(result.Findings));
    }

    private sealed class WaitingPolicy : IPolicyEngine
    {
        internal readonly TaskCompletionSource<bool> Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public PolicyEvaluationResult EvaluateFinding(SecurityFinding finding, string? filePath = null) => new();
        public Task<PolicyEvaluationResult> EvaluateFindingAsync(SecurityFinding finding, string? filePath = null,
            CancellationToken cancellationToken = default) => Task.FromResult(new PolicyEvaluationResult());
        public async Task<PolicyEvaluationResult> EnforcePolicyAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
        {
            Entered.TrySetResult(true);
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return new();
        }
    }

    [Theory]
    [InlineData("526172211A0700")]
    [InlineData("377ABCAF271C")]
    [InlineData("1F8B08000000")]
    [InlineData("FD377A585A00")]
    public async Task UnsupportedContainerHeader_CannotBecomeCleanByRenaming(string headerHex)
    {
        string path = Path.Combine(_root, "renamed.jpg");
        await File.WriteAllBytesAsync(path, Convert.FromHexString(headerHex));
        var hash = new HashService();
        var scanner = new FileScannerService(hash, new SignatureVerifier(), new RiskScoringEngine(),
            new AllowlistService(hash));
        var first = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(5));
        var repeated = await scanner.ScanFileDetailedAsync(path, TimeSpan.FromSeconds(5));
        Assert.Equal(FileScanOutcome.Failed, first.Outcome);
        Assert.Contains("kapsayıcının", first.ErrorMessage);
        Assert.Null(first.Finding);
        Assert.Equal(FileScanOutcome.Failed, repeated.Outcome);
        Assert.False(repeated.IsFromCache);
    }
}
