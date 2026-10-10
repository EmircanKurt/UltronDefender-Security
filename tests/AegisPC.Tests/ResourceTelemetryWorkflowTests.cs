using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Tests inert resource policies without changing machine settings or scanning user files.</summary>
public sealed class ResourceTelemetryWorkflowTests
{
    [Fact]
    public void Nominal16GiB_WithHardwareReservedRam_UsesHighAutoTier()
    {
        var p = ScanResourceProfile.Create(ScanResourceMode.Auto, false, 12, 17041334272L, 10, 25);
        Assert.Equal(4, p.Concurrency);
        Assert.True(p.MaxMemoryBudgetBytes <= 17041334272L * 0.60);
    }

    [Fact]
    public void EightGiBAndBusy16GiB_DoNotUseHighAutoTier()
    {
        Assert.Equal(4, ScanResourceProfile.Create(ScanResourceMode.Auto, false, 12, 8L << 30, 10, 25).Concurrency);
        Assert.Equal(1, ScanResourceProfile.Create(ScanResourceMode.Auto, false, 12, 17041334272L, 10, 92).Concurrency);
    }

    [Fact]
    public void EmptyQuickTarget_UsesSystemVolumeInsteadOfUnknownStorage()
    {
        string? sampled = null;
        Func<string, bool> storage = path => { sampled = path; return true; };
        using var manager = new AdaptiveScanResourceManager("C:\\", pressureSampler: () => (25, 10, false),
            enableTelemetryTimer: false, storageClassifier: storage);
        manager.ConfigureTarget("");
        Assert.Equal(Path.GetPathRoot(Environment.SystemDirectory), sampled);
        Assert.False(manager.ActiveProfile.IsHddRestricted);
    }

    [Fact]
    public async Task QueueStart_RefreshesPressureBeforeChoosingWorkers()
    {
        var manager = new RecordingManager();
        using var queue = new ScanQueueCoordinator(resourceManager: manager);
        await queue.ExecuteScanQueueDetailedAsync("", ScanType.Quick, _ => Task.CompletedTask,
            (_, _) => throw new InvalidOperationException("No files are produced."), new ConcurrentBag<SecurityFinding>(),
            (_, _, _, _, _, _) => { }, default);
        Assert.Equal(1, manager.RefreshCalls);
    }

    [Theory]
    [InlineData(200, 200, 4, 25)]
    [InlineData(2000, 100, 4, 100)]
    [InlineData(0, 250, 4, 0)]
    public void CpuTelemetry_NormalizesProcessCpuAcrossLogicalProcessors(int cpuMs, int wallMs, int cores, double expected)
    {
        var type = typeof(FileScannerService).Assembly.GetType("AegisPC.Security.Scanning.ScanProcessTelemetry");
        Assert.NotNull(type);
        var method = type.GetMethod("CalculateCpuPercent", BindingFlags.Static | BindingFlags.Public);
        Assert.NotNull(method);
        Assert.Equal(expected, (double)method.Invoke(null, new object[] { TimeSpan.FromMilliseconds(cpuMs), TimeSpan.FromMilliseconds(wallMs), cores })!);
    }

    [Fact]
    public void Scanner_ProducesRealCpuAndProcessWorkingSetTelemetry()
    {
        string text = File.ReadAllText(Path.Combine(FindRoot(), "src/AegisPC.Security/Scanning/FileScannerService.cs"));
        Assert.DoesNotContain("double ramMb = GC.GetTotalMemory(false)", text);
        Assert.Contains("CpuUsagePercent =", text);
        Assert.Contains("ResourceProfileName =", text);
    }

    [Fact]
    public void ProcessWorkingSetPeak_NeverFallsBelowAnObservedSample()
    {
        using var telemetry = new ScanProcessTelemetry();
        var first = telemetry.Sample();
        Assert.True(telemetry.PeakObservedWorkingSetMb >= first.WorkingSetMb);
        var previousPeak = telemetry.PeakObservedWorkingSetMb;
        var second = telemetry.Sample();
        Assert.True(telemetry.PeakObservedWorkingSetMb >= second.WorkingSetMb);
        Assert.True(telemetry.PeakObservedWorkingSetMb >= previousPeak);
    }

    [Fact]
    public void Splash_VisibleDurationIsLonger_AndBackgroundStartSkipsSplash()
    {
        string text = File.ReadAllText(Path.Combine(FindRoot(), "src/AegisPC.App/App.xaml.cs"));
        Assert.Contains("TimeSpan.FromMilliseconds(2600)", text);
        Assert.Contains("if (!IsStartMinimized)", text);
        Assert.DoesNotContain("DateTime splashStart", text);
    }

    [Fact]
    public void Service_RefreshExclusionsInvalidatesDetectionPolicy()
    {
        string text = File.ReadAllText(Path.Combine(FindRoot(), "src/AegisPC.Service/IPC/NamedPipeServer.cs"));
        Assert.Contains("RefreshExclusions", text);
        Assert.Contains("ReloadAsync", text);
        Assert.Contains("DetectionPolicyRevision.Invalidate()", text);
    }

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "AegisPC.sln"))) return dir.FullName;
        throw new DirectoryNotFoundException("Repository root was not found.");
    }

    private sealed class RecordingManager : IScanResourceManager
    {
        public int RefreshCalls;
        public ScanResourceMode CurrentMode => ScanResourceMode.Auto;
        public ScanResourceProfile ActiveProfile => ScanResourceProfile.Create(ScanResourceMode.VeryLow, false, 1, 1L << 30);
        public event Action<ScanResourceProfile>? ProfileChanged { add { } remove { } }
        public void SetMode(ScanResourceMode mode) { }
        public void ConfigureTarget(string path) { }
        public void RefreshProfile() => RefreshCalls++;
        public Task EnterWorkerSlotAsync(CancellationToken ct) => Task.CompletedTask;
        public void ExitWorkerSlot() { }
        public Task ApplyPacingAsync(int n, CancellationToken ct) => Task.CompletedTask;
    }
}
