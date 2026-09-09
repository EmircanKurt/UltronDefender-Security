using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class AdaptiveResourceManagerTests
    {
        [Fact]
        public void AdaptiveScanResourceManager_DefaultProfiles_HaveCorrectBounds()
        {
            var manager = new AdaptiveScanResourceManager();

            manager.SetMode(ScanResourceMode.VeryLow);
            var veryLow = manager.ActiveProfile;
            Assert.True(veryLow.MaxMemoryBudgetBytes <= 128L * 1024 * 1024, "VeryLow RAM budget must be at most 128 MB");
            Assert.True(veryLow.MaxMemoryBudgetBytes >= 64L * 1024 * 1024, "VeryLow RAM budget must be at least 64 MB");
            Assert.True(veryLow.DelayBetweenFilesMs >= 5, "VeryLow must have pacing delay");
            Assert.True(veryLow.YieldFrequency <= 20, "VeryLow must yield frequently");

            manager.SetMode(ScanResourceMode.Low);
            var low = manager.ActiveProfile;
            Assert.True(low.Concurrency >= 2, "Low must have at least 2 workers");
            Assert.True(low.MaxMemoryBudgetBytes >= 256L * 1024 * 1024, "Low RAM budget must be at least 256 MB");

            manager.SetMode(ScanResourceMode.Balanced);
            var balanced = manager.ActiveProfile;
            Assert.True(balanced.Concurrency >= 2, "Balanced must have at least 2 workers");
            // RAM bütçesi: RAM/3 oranında olmalı (16 GB'de ~5.3 GB, 8 GB'de ~2.6 GB)
            Assert.True(balanced.MaxMemoryBudgetBytes >= 256L * 1024 * 1024, "Balanced RAM budget must be at least 256 MB");

            manager.SetMode(ScanResourceMode.High);
            var high = manager.ActiveProfile;
            Assert.True(high.Concurrency >= 4, "High must have at least 4 workers");
            // RAM bütçesi: RAM/2 oranında olmalı (16 GB'de ~8 GB)
            Assert.True(high.MaxMemoryBudgetBytes > balanced.MaxMemoryBudgetBytes, "High RAM must be greater than Balanced");

            manager.SetMode(ScanResourceMode.Maximum);
            var max = manager.ActiveProfile;
            Assert.True(max.Concurrency >= Environment.ProcessorCount, "Maximum concurrency must use at least all cores");
            Assert.Equal(0, max.DelayBetweenFilesMs);
            Assert.True(max.MaxMemoryBudgetBytes >= high.MaxMemoryBudgetBytes, "Maximum RAM must be >= High");
        }

        [Fact]
        public void AdaptiveScanResourceManager_RamBudget_ScalesWithSystemRam()
        {
            var manager = new AdaptiveScanResourceManager();

            // Test that High/Maximum modes allocate proportional RAM budgets
            manager.SetMode(ScanResourceMode.High);
            var high = manager.ActiveProfile;

            // RAM/2 oranı kontrolü: 8 GB RAM'de bile en az 3 GB bütçe olmalı
            long expectedMinHighBudget = 3L * 1024 * 1024 * 1024;
            Assert.True(high.MaxMemoryBudgetBytes >= expectedMinHighBudget,
                $"High mode RAM budget ({high.MaxMemoryBudgetBytes / (1024 * 1024)} MB) must be at least {expectedMinHighBudget / (1024 * 1024)} MB on this system");

            manager.SetMode(ScanResourceMode.Maximum);
            var maximum = manager.ActiveProfile;
            Assert.True(maximum.MaxMemoryBudgetBytes >= high.MaxMemoryBudgetBytes,
                "Maximum mode must have >= High mode RAM budget");
        }

        [Fact]
        public void AdaptiveScanResourceManager_DynamicModeTransition_UpdatesActiveProfile()
        {
            var manager = new AdaptiveScanResourceManager();
            Assert.Equal(ScanResourceMode.Auto, manager.CurrentMode);

            manager.SetMode(ScanResourceMode.High);
            Assert.Equal(ScanResourceMode.High, manager.CurrentMode);
            Assert.Equal("High", manager.ActiveProfile.Name);

            manager.SetMode(ScanResourceMode.VeryLow);
            Assert.Equal(ScanResourceMode.VeryLow, manager.CurrentMode);
            Assert.True(manager.ActiveProfile.Concurrency >= 1);
        }

        [Fact]
        public async Task AdaptiveScanResourceManager_SlotAcquisition_EnforcesConcurrencyLimits()
        {
            var manager = new AdaptiveScanResourceManager();
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

        [Fact]
        public void AdaptiveScanResourceManager_HighMode_AggressiveConcurrency()
        {
            var manager = new AdaptiveScanResourceManager();
            manager.SetMode(ScanResourceMode.High);
            var profile = manager.ActiveProfile;

            int cores = Environment.ProcessorCount;

            // High modda en az cores-1 worker olmalı (4'ten az olamaz)
            Assert.True(profile.Concurrency >= Math.Max(4, cores - 1),
                $"High mode should use at least {Math.Max(4, cores - 1)} workers on {cores}-core system, got {profile.Concurrency}");

            // Gecikme olmamalı
            Assert.Equal(0, profile.DelayBetweenFilesMs);
        }
    }
}
