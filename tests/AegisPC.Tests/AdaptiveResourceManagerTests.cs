using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class AdaptiveResourceManagerTests
    {
        private const long MiB = 1024L * 1024;
        private const long GiB = 1024L * MiB;

        /// <summary>Checks mode preferences on a controlled SSD without conflating host pressure with policy defaults.</summary>
        [Fact]
        public void AdaptiveScanResourceManager_DefaultProfiles_HaveCorrectBounds()
        {
            var veryLow = ScanResourceProfile.Create(ScanResourceMode.VeryLow, false, 8, 16 * GiB);
            Assert.True(veryLow.MaxMemoryBudgetBytes <= 128L * 1024 * 1024, "VeryLow RAM budget must be at most 128 MB");
            Assert.True(veryLow.MaxMemoryBudgetBytes >= 64L * 1024 * 1024, "VeryLow RAM budget must be at least 64 MB");
            Assert.True(veryLow.DelayBetweenFilesMs >= 5, "VeryLow must have pacing delay");
            Assert.True(veryLow.YieldFrequency <= 20, "VeryLow must yield frequently");

            var low = ScanResourceProfile.Create(ScanResourceMode.Low, false, 8, 16 * GiB);
            Assert.True(low.Concurrency >= 2, "Low must have at least 2 workers");
            Assert.True(low.MaxMemoryBudgetBytes >= 256L * 1024 * 1024, "Low RAM budget must be at least 256 MB");

            var balanced = ScanResourceProfile.Create(ScanResourceMode.Balanced, false, 8, 16 * GiB);
            Assert.True(balanced.Concurrency >= 2, "Balanced must have at least 2 workers");
            Assert.True(balanced.MaxMemoryBudgetBytes >= 256L * 1024 * 1024, "Balanced RAM budget must be at least 256 MB");

            var high = ScanResourceProfile.Create(ScanResourceMode.High, false, 8, 16 * GiB);
            Assert.True(high.Concurrency >= 4, "High must have at least 4 workers");
            Assert.Equal(2 * GiB, high.MaxMemoryBudgetBytes);

            var max = ScanResourceProfile.Create(ScanResourceMode.Maximum, false, 8, 16 * GiB);
            Assert.True(max.Concurrency >= 8, "An unpressured SSD fixture must permit at least its eight logical cores");
            Assert.Equal(0, max.DelayBetweenFilesMs);
            Assert.True(max.MaxMemoryBudgetBytes >= high.MaxMemoryBudgetBytes, "Maximum RAM must be >= High");
        }

        /// <summary>Checks RAM scaling and headroom caps using known capacities and pressure, including low-memory machines.</summary>
        [Fact]
        public void AdaptiveScanResourceManager_RamBudget_ScalesWithSystemRam()
        {
            foreach (var mode in new[] { ScanResourceMode.High, ScanResourceMode.Maximum })
            {
                long previousUnpressuredBudget = 0;
                foreach (long ramGiB in new long[] { 2, 4, 8, 16, 32 })
                {
                    long totalRam = ramGiB * GiB;
                    var unpressured = ScanResourceProfile.Create(mode, false, 8, totalRam);
                    Assert.True(unpressured.MaxMemoryBudgetBytes >= previousUnpressuredBudget,
                        $"{mode} must not reduce its budget when otherwise identical physical RAM increases.");
                    previousUnpressuredBudget = unpressured.MaxMemoryBudgetBytes;

                    foreach (double pressure in new double[] { 0, 60, 90 })
                    {
                        var profile = ScanResourceProfile.Create(mode, false, 8, totalRam, memoryPressurePercent: pressure);
                        long physicalCapMiB = Math.Min(totalRam / MiB * 3 / 5, 16384);
                        long availableCapMiB = (long)(totalRam / MiB * (100 - pressure) / 100 * 0.75);
                        Assert.InRange(profile.MaxMemoryBudgetBytes, MiB, Math.Min(physicalCapMiB, availableCapMiB) * MiB);
                        Assert.InRange(profile.Concurrency, 1, Math.Min(32, Math.Max(1, (int)(profile.MaxMemoryBudgetBytes / (64 * MiB)))));
                        Assert.Equal(mode, profile.Mode);
                        if (pressure >= 88)
                        {
                            Assert.Equal(1, profile.Concurrency);
                            Assert.True(profile.MaxMemoryBudgetBytes <= 128 * MiB);
                        }
                    }
                }
            }

            Assert.Equal(512 * MiB, ScanResourceProfile.Create(ScanResourceMode.High, false, 8, 8 * GiB).MaxMemoryBudgetBytes);
            Assert.Equal(2 * GiB, ScanResourceProfile.Create(ScanResourceMode.High, false, 8, 16 * GiB).MaxMemoryBudgetBytes);
        }

        /// <summary>Checks requested mode changes while a fixed pressure sampler prevents timer-driven host-dependent transitions.</summary>
        [Fact]
        public void AdaptiveScanResourceManager_DynamicModeTransition_UpdatesActiveProfile()
        {
            using var manager = new AdaptiveScanResourceManager(pressureSampler: () => (0, 0, false), enableTelemetryTimer: false);
            Assert.Equal(ScanResourceMode.Auto, manager.CurrentMode);

            manager.SetMode(ScanResourceMode.High);
            Assert.Equal(ScanResourceMode.High, manager.CurrentMode);
            Assert.Equal("High", manager.ActiveProfile.Name);

            manager.SetMode(ScanResourceMode.VeryLow);
            Assert.Equal(ScanResourceMode.VeryLow, manager.CurrentMode);
            Assert.True(manager.ActiveProfile.Concurrency >= 1);
        }

        /// <summary>Checks real semaphore admission and release with background telemetry disabled for a stable permit count.</summary>
        [Fact]
        public async Task AdaptiveScanResourceManager_SlotAcquisition_EnforcesConcurrencyLimits()
        {
            using var manager = new AdaptiveScanResourceManager(pressureSampler: () => (0, 0, false), enableTelemetryTimer: false);
            manager.SetMode(ScanResourceMode.VeryLow);

            int veryLowConcurrency = manager.ActiveProfile.Concurrency;

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            // Acquire all available slots
            for (int i = 0; i < veryLowConcurrency; i++)
            {
                await manager.EnterWorkerSlotAsync(cts.Token);
            }

            // Next slot should be blocked
            bool acquiredExtra = false;
            var acquireTask = Task.Run(async () =>
            {
                await manager.EnterWorkerSlotAsync(cts.Token);
                acquiredExtra = true;
                manager.ExitWorkerSlot();
            });

            await Task.Delay(100);
            Assert.False(acquiredExtra, $"Extra worker slot must be blocked when all {veryLowConcurrency} slots are used.");

            // Release one slot
            manager.ExitWorkerSlot();
            await acquireTask;
            Assert.True(acquiredExtra, "Worker slot should be acquired after one exits.");

            // Release remaining slots
            for (int i = 1; i < veryLowConcurrency; i++)
            {
                manager.ExitWorkerSlot();
            }
        }

        /// <summary>Checks SSD expansion and rotational-disk pacing on otherwise identical deterministic hardware.</summary>
        [Fact]
        public void AdaptiveScanResourceManager_HighMode_AggressiveConcurrency()
        {
            var profile = ScanResourceProfile.Create(ScanResourceMode.High, false, 8, 16 * GiB);
            Assert.Equal(8, profile.Concurrency);
            Assert.False(profile.IsHddRestricted);
            Assert.Equal(0, profile.DelayBetweenFilesMs);

            var rotational = ScanResourceProfile.Create(ScanResourceMode.High, true, 8, 16 * GiB);
            Assert.Equal(2, rotational.Concurrency);
            Assert.True(rotational.IsHddRestricted);
            Assert.Equal(0, rotational.DelayBetweenFilesMs); // Seek limits, not artificial per-file sleeps, constrain HDD admission.
        }
    }
}
