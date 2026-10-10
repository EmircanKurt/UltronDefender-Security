using System.Reflection;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert presentation regressions: no Windows service, scan files, protection actions or real UI is launched.</summary>
public sealed class SilentScanPresentationReviewTests
{
    /// <summary>Missing history is empty after a successful read; malformed history never shows the empty state.</summary>
    [Fact]
    public async Task HistoryFailureDoesNotMasqueradeAsEmpty()
    {
        string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "UltronHistoryProbe-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var vm = new ScanViewModel(reportHistoryStore: new AegisPC.App.Services.ScanReportHistoryStore(path), presentScanner: () => { });
            Assert.False(vm.IsReportHistoryEmpty);
            await vm.RefreshReportsAsync(); Assert.True(vm.IsReportHistoryEmpty);
            await System.IO.File.WriteAllTextAsync(path, "{");
            await vm.RefreshReportsAsync();
            Assert.False(vm.IsReportHistoryEmpty);
            Assert.Contains("Rapor geçmişi okunamadı", vm.ReportHistoryStatus);
        }
        finally { if (System.IO.File.Exists(path)) System.IO.File.Delete(path); }
    }

    /// <summary>Opening the dashboard registers sweep observation but never requests the old delayed startup scan.</summary>
    [Fact]
    public async Task DashboardOpeningDoesNotScheduleSweep()
    {
        var sweep = new SweepProbe();
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        var vm = new DashboardViewModel(startupSweepService: sweep, scanCoordinator: coordinator);
        await Task.Delay(3100);
        Assert.Equal(0, sweep.Requests);
        Assert.Equal(3, sweep.Subscriptions);
        Assert.Equal(0, scanner.StartCount);
        Assert.False(vm.IsStartupSweepRunning);
        Assert.Equal(0, vm.StartupSweepProgressPercent);
        Assert.Equal("Açılış taraması kapalı", vm.StartupSweepStatusText);
    }

    /// <summary>Observing already-running background work, progress, sync and completion never requests a foreground view.</summary>
    [Fact]
    public async Task BackgroundSessionAndProgressStaySilent()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int foreground = 0;
        var first = new ScanViewModel(scanCoordinator: coordinator, presentScanner: () => foreground++);
        var scan = ((IBackgroundScanCoordinator)coordinator).TryStartBackgroundScanAsync(ScanType.Quick, CancellationToken.None);
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var reopened = new ScanViewModel(scanCoordinator: coordinator, presentScanner: () => foreground++);
        first.SyncWithScanCoordinator(); reopened.SyncWithScanCoordinator();
        typeof(ScanViewModel).GetMethod("OnScanProgressChanged", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(first, [new ScanProgress { ScanType = ScanType.Quick, ScannedFiles = 17, CurrentFile = "inert-example.txt" }]);
        Assert.True(first.IsScanning); Assert.True(reopened.IsScanning);
        Assert.Equal(17, first.ScannedCount);
        Assert.Equal(0, foreground);
        scanner.Complete.TrySetResult(true);
        await scan.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(first.IsScanning);
        Assert.True(first.IsScanFinishedView);
        Assert.Equal(0, foreground);
    }

    /// <summary>A manual custom-path request reveals the shared scanner once; progress and completion do not reveal it again.</summary>
    [Fact]
    public async Task ExplicitScanRevealsSharedScannerOnly()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int foreground = 0;
        var vm = new ScanViewModel(scanCoordinator: coordinator, presentScanner: () => foreground++);
        Assert.Equal(0, foreground);
        var manual = vm.StartCustomPathScanAsync("inert-supplied-path");
        await scanner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, foreground); Assert.True(vm.IsScanning);
        vm.SyncWithScanCoordinator(); Assert.Equal(1, foreground);
        scanner.Complete.TrySetResult(true); await manual.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(vm.IsScanFinishedView); Assert.Equal(1, foreground);
        vm.CloseResults(); Assert.True(vm.IsIdleView);
    }

    /// <summary>Opening the scanner is a navigation-only request, not a scan request.</summary>
    [Fact]
    public async Task OpenScannerDoesNotStartScan()
    {
        var scanner = new FinalReviewScanRegressionTests.ControlledScanner();
        var coordinator = new ScanCoordinatorService(scanner, new SecurityFindingService());
        int foreground = 0;
        var vm = new ScanViewModel(scanCoordinator: coordinator, presentScanner: () => foreground++);
        await vm.OpenActiveScanWindowAsync();
        Assert.Equal(1, foreground); Assert.Equal(0, scanner.StartCount); Assert.True(vm.IsIdleView);
    }

    private sealed class SweepProbe : IStartupSecuritySweepService
    {
        public int Requests; public int Subscriptions;
        public StartupSweepStatus Status => StartupSweepStatus.NotStarted;
        public bool IsRunning => false; public bool IsPaused => false;
        public StartupSweepResult? LastResult => null;
        public event Action<StartupSweepProgress>? OnProgressChanged { add => Subscriptions++; remove => Subscriptions--; }
        public event Action<StartupSweepFinding>? OnThreatDiscovered { add => Subscriptions++; remove => Subscriptions--; }
        public event Action<StartupSweepResult>? OnSweepCompleted { add => Subscriptions++; remove => Subscriptions--; }
        public Task<StartupSweepResult> RunSweepAsync(IEnumerable<string>? customTargetDirs = null, CancellationToken cancellationToken = default)
        { Requests++; return Task.FromResult(new StartupSweepResult()); }
        public void Pause() { } public void Resume() { } public void Cancel() { }
    }
}
