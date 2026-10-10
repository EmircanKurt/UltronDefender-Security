using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using AegisPC.Service.Scheduler;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Deterministic resource-policy regressions; these are not physical hardware benchmarks.</summary>
public sealed class AdaptiveIdleReviewTests
{
    [Fact]
    public void DefaultProfile_UsesAdaptiveMode()
    {
        Assert.Equal(ScanResourceMode.Auto, ScanResourceProfile.CreateDefault().Mode);
    }

    [Theory]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(512)]
    public void EveryProfile_RespectsActualSmallMemoryCapacity(int totalMb)
    {
        long totalBytes = totalMb * 1024L * 1024;
        foreach (var mode in Enum.GetValues<ScanResourceMode>())
        {
            var profile = ScanResourceProfile.Create(mode, false, 16, totalBytes);
            Assert.InRange(profile.MaxMemoryBudgetBytes, 1, totalBytes * 3 / 5);
        }
    }

    [Theory]
    [InlineData(70)]
    [InlineData(87)]
    [InlineData(95)]
    public void MaximumProfile_PreservesHeadroomInAvailableMemory(double pressure)
    {
        long totalBytes = 8L * 1024 * 1024 * 1024;
        var profile = ScanResourceProfile.Create(ScanResourceMode.Maximum, false, 16,
            totalBytes, memoryPressurePercent: pressure);
        long availableBytes = (long)(totalBytes * (100 - pressure) / 100);
        Assert.True(profile.MaxMemoryBudgetBytes <= availableBytes * 3 / 4);
    }

    [Fact]
    public void Refresh_ThrottlesManualMaximumWhenPressureRises()
    {
        double pressure = 10;
        using var manager = new AdaptiveScanResourceManager(pressureSampler: () => (pressure, 10, false),
            enableTelemetryTimer: false);
        manager.SetMode(ScanResourceMode.Maximum);
        long initialBudget = manager.ActiveProfile.MaxMemoryBudgetBytes;
        pressure = 95;
        manager.RefreshProfile();
        Assert.Equal(ScanResourceMode.Maximum, manager.CurrentMode);
        Assert.Equal(1, manager.ActiveProfile.Concurrency);
        Assert.True(manager.ActiveProfile.MaxMemoryBudgetBytes < initialBudget);
    }

    [Fact]
    public async Task Dispose_CancelsAWorkerWaitingForTheOccupiedSlot()
    {
        var manager = new AdaptiveScanResourceManager(enableTelemetryTimer: false);
        manager.SetMode(ScanResourceMode.VeryLow);
        await manager.EnterWorkerSlotAsync(CancellationToken.None);
        Task waiting = manager.EnterWorkerSlotAsync(CancellationToken.None);
        Assert.False(waiting.IsCompleted);
        manager.Dispose();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(TimeSpan.FromSeconds(2)));
        manager.ExitWorkerSlot();
    }

    [Fact]
    public void LocalInputTicks_RolloverDoesNotProduceFortyNineDaysOfIdle()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(151), IdleDetector.CalculateLocalIdleDuration(100, uint.MaxValue - 50));
        Assert.Null(IdleDetector.CalculateLocalIdleDuration(100, 200));
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(100, 0)]
    [InlineData(100, 200)]
    public void SessionIdle_InvalidNativeTimestampsCannotAuthorizeAfk(long now, long last)
    {
        Assert.Null(IdleDetector.CalculateSessionIdleDuration(now, last));
    }

    [Fact]
    public void SessionIdle_UsesOneHundredNanosecondTimestampUnits()
    {
        long now = DateTime.UtcNow.ToFileTimeUtc();
        Assert.Equal(TimeSpan.FromMinutes(15), IdleDetector.CalculateSessionIdleDuration(now, now - TimeSpan.FromMinutes(15).Ticks));
    }

    [Fact]
    public void HardwarePresentation_UsesTheSameCappedProfileAsTheEngine()
    {
        var hardware = ScanHardwareProfile.Detect(isSsd: false);
        Assert.InRange(hardware.Concurrency, 1, 2);
        Assert.True(hardware.MaxMemoryBudgetBytes <= hardware.TotalRamGb * 1024 * 1024 * 1024 * 0.6);
        Assert.True(hardware.CpuCores >= 1);
    }

    [Fact]
    public void MaximumOnManyCores_ReservesMemoryHeadroomPerWorkerUnderPressure()
    {
        var profile = ScanResourceProfile.Create(ScanResourceMode.Maximum, false, 64,
            8L * 1024 * 1024 * 1024, memoryPressurePercent: 87);
        Assert.True(profile.Concurrency <= Math.Max(1, profile.MaxMemoryBudgetBytes / (64L * 1024 * 1024)));
    }
}
