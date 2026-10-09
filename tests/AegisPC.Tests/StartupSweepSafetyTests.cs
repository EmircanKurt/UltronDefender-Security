using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.App.ViewModels;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Uses only benign temporary bytes and recording fakes; never invokes a real vault or process action.</summary>
public sealed partial class StartupSweepSafetyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "UltronStartupSafety_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task BusyManualCoordinator_DefersSweepWithoutInspectingOrPublishingCompletion()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean });
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var manual = coordinator.TryStartManualScanAsync(ScanType.Full, string.Empty, () => { });
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var session = coordinator.CurrentSession;
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault(), scanCoordinator: coordinator);
        int completedEvents = 0;
        sweep.OnSweepCompleted += _ => completedEvents++;

        var result = await sweep.RunSweepAsync(new[] { file });

        Assert.Equal(StartupSweepStatus.Busy, result.FinalStatus);
        Assert.Equal(0, engine.Inspections);
        Assert.Equal(0, completedEvents);
        Assert.Null(sweep.LastResult);
        Assert.Same(session, coordinator.CurrentSession);
        Assert.Equal(ScanType.Full, coordinator.CurrentScanType);
        scanner.Complete.TrySetResult(true);
        await manual.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task QueuedSweep_DoesNotReplaceActiveCancellationOrExternalClaim()
    {
        string file = CreateBenignFile();
        string sha = ValidHash(file);
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.Clean,
            InspectionComplete = true,
            RecommendedPolicy = RealTimePolicyAction.Allow,
            SHA256 = sha
        });
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault(), scanCoordinator: coordinator);
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        int preparingCount = 0;
        sweep.OnProgressChanged += progress =>
        {
            if (progress.Status == StartupSweepStatus.Preparing && Interlocked.Increment(ref preparingCount) == 1)
            {
                entered.Set();
                if (!release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Synthetic sweep gate timed out.");
            }
        };

        var first = Task.Run(() => sweep.RunSweepAsync(new[] { file }));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
            var secondEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var second = Task.Run(async () =>
            {
                var pending = sweep.RunSweepAsync(new[] { file });
                secondEntered.TrySetResult(true);
                return await pending;
            });
            await secondEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(coordinator.IsExternalScanRunning);

            sweep.Cancel();
            release.Set();
            var firstResult = await first.WaitAsync(TimeSpan.FromSeconds(10));
            var secondResult = await second.WaitAsync(TimeSpan.FromSeconds(10));

            Assert.Equal(StartupSweepStatus.Cancelled, firstResult.FinalStatus);
            Assert.Equal(StartupSweepStatus.Clean, secondResult.FinalStatus);
            Assert.False(coordinator.IsExternalScanRunning);
        }
        finally
        {
            release.Set();
        }
    }

    [Fact]
    public async Task HighScoreWithoutConfirmedVerdictWarnsButNeverQuarantines()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.Suspicious,
            RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
            RiskScore = 100,
            SHA256 = ValidHash(file)
        });
        var vault = new RecordingVault();
        var coordinator = new RecordingCoordinator();

        var result = await new StartupSecuritySweepService(engine, vault, scanCoordinator: coordinator)
            .RunSweepAsync(new[] { file });

        Assert.Equal(1, result.SuspiciousCount);
        Assert.Equal(0, result.ThreatsCount);
        Assert.Equal("WARN", Assert.Single(result.Findings).Action);
        Assert.Equal(0, vault.BoundCalls + vault.UnboundCalls);
        Assert.True(File.Exists(file));
        Assert.Equal(RiskLevel.HighRisk, Assert.Single(Assert.IsType<ScanResult>(coordinator.LastResult).Findings).RiskLevel);
    }

    [Fact]
    public async Task ConfirmedExactVerdictUsesOnlyHashBoundQuarantine()
    {
        string file = CreateBenignFile();
        string sha = ValidHash(file);
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.ConfirmedMalicious,
            RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
            RiskScore = 95,
            SHA256 = sha
        });
        var vault = new RecordingVault { BoundResult = true };

        var result = await new StartupSecuritySweepService(engine, vault).RunSweepAsync(new[] { file });

        Assert.Equal(1, result.ThreatsCount);
        Assert.Equal(1, vault.BoundCalls);
        Assert.Equal(0, vault.UnboundCalls);
        Assert.Equal(sha, vault.LastExpectedHash);
        Assert.True(Assert.Single(result.Findings).IsQuarantined);
        Assert.True(File.Exists(file)); // The recording fake must not mutate anything.
    }

    [Theory]
    [InlineData(false, 85, 100)]
    [InlineData(true, 95, 90)]
    public async Task UserAutoQuarantinePreferenceAndThresholdAreRespected(bool enabled, int threshold, int score)
    {
        string file = CreateBenignFile();
        var settings = new SettingsService(Path.Combine(_dir, "unused-settings.json"));
        settings.SetSetting("EnableAutoQuarantine", enabled);
        settings.SetSetting("AutoQuarantineThreshold", threshold);
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.ConfirmedMalicious,
            RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
            RiskScore = score,
            SHA256 = ValidHash(file)
        });
        var vault = new RecordingVault { BoundResult = true };

        var result = await new StartupSecuritySweepService(engine, vault, settingsService: settings)
            .RunSweepAsync(new[] { file });

        Assert.Equal(1, result.ThreatsCount);
        Assert.Equal(0, vault.BoundCalls + vault.UnboundCalls);
        Assert.Equal("REVIEW_REQUIRED", Assert.Single(result.Findings).Action);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task ConfirmedVerdictWithoutBoundCapabilityNeverFallsBackToUnboundVault()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.ConfirmedMalicious,
            RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
            RiskScore = 95,
            SHA256 = ValidHash(file)
        });
        var vault = new LegacyVault();

        var result = await new StartupSecuritySweepService(engine, vault).RunSweepAsync(new[] { file });

        Assert.Equal(0, vault.UnboundCalls);
        Assert.False(Assert.Single(result.Findings).IsQuarantined);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task InvalidHashCannotAuthorizeAutomaticQuarantine()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.ConfirmedMalicious,
            RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
            RiskScore = 100,
            SHA256 = "not-a-sha256"
        });
        var vault = new RecordingVault();

        var result = await new StartupSecuritySweepService(engine, vault).RunSweepAsync(new[] { file });

        Assert.Equal(0, vault.BoundCalls + vault.UnboundCalls);
        Assert.False(Assert.Single(result.Findings).IsQuarantined);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task StaleConfirmedHashIsNotReportedAsCurrentThreatOrQuarantined()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.ConfirmedMalicious,
            RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine,
            RiskScore = 100,
            SHA256 = new string('A', 64)
        });
        var vault = new RecordingVault { BoundResult = true };

        var result = await new StartupSecuritySweepService(engine, vault).RunSweepAsync(new[] { file });

        Assert.Equal(0, result.ThreatsCount);
        Assert.Equal(1, result.SuspiciousCount);
        Assert.Equal(0, vault.BoundCalls + vault.UnboundCalls);
        Assert.True(File.Exists(file));
    }

    [Fact]
    public async Task UnknownInspectionIsNotReportedOrCachedAsClean()
    {
        string file = CreateBenignFile();
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.Unknown,
            RecommendedPolicy = RealTimePolicyAction.Allow,
            RiskScore = 0
        });
        var vault = new RecordingVault();
        var coordinator = new RecordingCoordinator();
        var sweep = new StartupSecuritySweepService(engine, vault, scanCoordinator: coordinator);

        var first = await sweep.RunSweepAsync(new[] { file });
        var second = await sweep.RunSweepAsync(new[] { file });

        Assert.Equal(0, first.CleanCount);
        Assert.Equal(StartupSweepStatus.Completed, first.FinalStatus);
        Assert.Equal(1, first.IncompleteCount);
        Assert.Equal(0, first.SuspiciousCount);
        Assert.Equal("INCOMPLETE", Assert.Single(first.Findings).Action);
        Assert.Equal(2, engine.Inspections);
        Assert.Equal(0, second.SkippedCount);
        Assert.Equal(ScanStatus.Completed, Assert.IsType<ScanResult>(coordinator.LastResult).Status);
        Assert.Equal(1, coordinator.LastResult.FailedFiles);
        Assert.False(coordinator.LastResult.Coverage.IsComplete);
        Assert.Empty(coordinator.LastResult.Findings);
    }

    [Fact]
    public async Task ChangedBytesWithUnchangedLengthAndTimestampAreRescanned()
    {
        string file = CreateBenignFile("first-benign-bytes");
        var engine = new RecordingEngine(_ => new RealTimeVerdictResult
        {
            Verdict = RealTimeVerdict.Clean,
            InspectionComplete = true,
            RecommendedPolicy = RealTimePolicyAction.Allow,
            RiskScore = 0
        });
        var sweep = new StartupSecuritySweepService(engine, new RecordingVault());
        DateTime stamp = File.GetLastWriteTimeUtc(file);

        await sweep.RunSweepAsync(new[] { file });
        File.WriteAllText(file, "other-benign-bytes");
        File.SetLastWriteTimeUtc(file, stamp);
        var second = await sweep.RunSweepAsync(new[] { file });

        Assert.Equal(2, engine.Inspections);
        Assert.Equal(0, second.SkippedCount);
    }

    [Theory]
    [InlineData(StartupSweepStatus.Completed, 0, 2, "inceleme bekleyen", "#F5A623")]
    [InlineData(StartupSweepStatus.Failed, 1, 0, "tamamlanamadı", "#F5A623")]
    [InlineData(StartupSweepStatus.Completed, 1, 0, "incelemesi eksik", "#F5A623")]
    [InlineData(StartupSweepStatus.Clean, 0, 0, "bulgu yok", "#4CAF50")]
    public void DashboardStartupSummaryDoesNotCallSuspicionOrIncompleteScanClean(
        StartupSweepStatus status, int incomplete, int suspicious, string expectedText, string expectedColor)
    {
        var format = typeof(DashboardViewModel).GetMethod("GetStartupSweepSummary", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(format);
        var result = new StartupSweepResult
        {
            FinalStatus = status,
            IncompleteCount = incomplete,
            SuspiciousCount = suspicious
        };
        var (text, color) = Assert.IsType<ValueTuple<string, string>>(format.Invoke(null, new object[] { result }));
        Assert.Contains(expectedText, text, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expectedColor, color);
    }

    private string CreateBenignFile(string contents = "simple benign data")
    {
        Directory.CreateDirectory(_dir);
        string path = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(path, contents);
        return path;
    }

    private static string ValidHash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));


    public void Dispose()
    {
        string full = Path.GetFullPath(_dir);
        if (full.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase) && Directory.Exists(full))
            Directory.Delete(full, recursive: true);
    }

    private sealed class RecordingEngine(Func<string, RealTimeVerdictResult> inspect) : IRealTimeProtectionEngine
    {
        public Func<string, CancellationToken, Task<RealTimeVerdictResult>>? AsyncInspect { get; set; }
        public int Inspections { get; private set; }
        public bool IsRunning => false;
        public IReadOnlyList<string> WatchedLocations => Array.Empty<string>();
        public event Action<SecurityFinding>? OnThreatDetected { add { } remove { } }
        public event Action<SecurityIncident>? OnIncidentCreated { add { } remove { } }
        public event Action<string, string, string>? OnNotificationRaised { add { } remove { } }
        public event Action<RealTimeActivityEvent>? OnActivityLogged { add { } remove { } }
        public event Action<bool, string>? OnProtectionHealthChanged { add { } remove { } }
        public void Start() { }
        public void Stop() { }
        public void AddWatchDirectory(string path) { }
        public void RemoveWatchDirectory(string path) { }
        public Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            Inspections++;
            return AsyncInspect?.Invoke(filePath, cancellationToken) ?? Task.FromResult(inspect(filePath));
        }
    }

    private class LegacyVault : IQuarantineService
    {
        public int UnboundCalls { get; private set; }
        public string? LastError => null;
        public event Action<QuarantineEntry>? OnFileQuarantined { add { } remove { } }
        public event Action<int>? OnFileRestored { add { } remove { } }
        public event Action<int>? OnFileDeleted { add { } remove { } }
        public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default)
        {
            UnboundCalls++;
            return Task.FromResult(true);
        }
        public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<QuarantineEntry>());
        public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult<QuarantineEntry?>(null);
    }

    private sealed class RecordingVault : LegacyVault, IContentBoundQuarantineService
    {
        public int BoundCalls { get; private set; }
        public string? LastExpectedHash { get; private set; }
        public bool BoundResult { get; set; }
        public Task<bool> TryQuarantineFileAsync(string path, string reason, string expectedSha256, CancellationToken cancellationToken = default)
        {
            BoundCalls++;
            LastExpectedHash = expectedSha256;
            return Task.FromResult(BoundResult);
        }
    }

    private sealed class RecordingCoordinator : IScanCoordinatorService
    {
        public ScanResult? LastResult { get; private set; }
        public bool IsScanning => false;
        public ScanState State => default;
        public ScanStopReason StopReason => default;
        public ScanType CurrentScanType => default;
        public double ProgressPercent => 0;
        public string CurrentFile => string.Empty;
        public int ScannedFiles => 0;
        public int TotalFiles => 0;
        public int FindingsCount => 0;
        public string StatusText => string.Empty;
        public IReadOnlyList<SecurityFinding> CurrentFindings => LastResult is null
            ? Array.Empty<SecurityFinding>() : LastResult.Findings;
        public bool IsPaused => false;
        public TimeSpan ElapsedTime => TimeSpan.Zero;
        public IScanSession? CurrentSession => null;
        public event Action<IScanSession>? ScanSessionStarted { add { } remove { } }
        public event Action<ScanProgress>? ProgressChanged { add { } remove { } }
        public event Action<ScanResult>? ScanCompleted { add { } remove { } }
        public Task<ScanResult?> StartScanAsync(ScanType scanType, string customPath = "") => Task.FromResult<ScanResult?>(null);
        public IExternalScanRegistration TryRegisterExternalScanner(Action pauseAction, Action resumeAction, Action cancelAction) =>
            new RecordingRegistration(this);
        public IDisposable RegisterExternalScanner(Action pauseAction, Action resumeAction, Action cancelAction) =>
            TryRegisterExternalScanner(pauseAction, resumeAction, cancelAction);
        public void RegisterExternalScanProgress(ScanProgress progress) { }
        public void CompleteExternalScan(ScanResult result) => LastResult = result;
        public void PauseScan() { }
        public void ResumeScan() { }
        public void CancelScan() { }

        private sealed class RecordingRegistration : IExternalScanRegistration
        {
            private readonly RecordingCoordinator _owner;
            private bool _disposed;

            public RecordingRegistration(RecordingCoordinator owner) => _owner = owner;
            public bool ReportProgress(ScanProgress progress) => !_disposed;
            public bool Complete(ScanResult result)
            {
                if (_disposed) return false;
                _disposed = true;
                _owner.LastResult = result;
                return true;
            }
            public void Dispose() => _disposed = true;
        }
    }
}
