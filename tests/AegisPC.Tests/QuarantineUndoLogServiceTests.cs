using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using Xunit;

namespace AegisPC.Tests
{
    public class QuarantineUndoLogServiceTests : IDisposable
    {
        private class FakeQuarantineService : IQuarantineService
        {
#pragma warning disable CS0067
            public event Action<QuarantineEntry>? OnFileQuarantined;
            public event Action<int>? OnFileRestored;
            public event Action<int>? OnFileDeleted;
#pragma warning restore CS0067

            public string? LastError { get; set; }
            public List<int> RestoredIds { get; } = new();

            public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default)
                => Task.FromResult(true);

            public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default)
            {
                RestoredIds.Add(id);
                return Task.FromResult(true);
            }

            public Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default)
            {
                RestoredIds.Add(id);
                return Task.FromResult(true);
            }

            public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default)
                => Task.FromResult(new List<QuarantineEntry>());

            public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
                => Task.FromResult(true);

            public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default)
                => Task.FromResult<QuarantineEntry?>(null);
        }

        private readonly string _testDir;
        private readonly FakeQuarantineService _fakeQuarantineService;

        public QuarantineUndoLogServiceTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "AegisPC_UndoLogTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
            _fakeQuarantineService = new FakeQuarantineService();
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task RecordQuarantineDecisionAsync_StoresAndRetrievesDecisionChain()
        {
            var service = new QuarantineUndoLogService(_fakeQuarantineService, customStoragePath: _testDir);

            string path = @"C:\Users\Test\malware.exe";
            string chain = "Risk Skoru: 95/100, Detector: YARA, Politika: Otomatik Karantina";
            await service.RecordQuarantineDecisionAsync(101, path, 95, "Trojan.Generic", chain);

            var retrievedChain = await service.GetDecisionChainAsync(101);
            Assert.Equal(chain, retrievedChain);

            var entries = await service.GetUndoLogEntriesAsync();
            Assert.Single(entries);
            Assert.Equal(101, entries[0].QuarantineId);
            Assert.Equal("malware.exe", entries[0].FileName);
            Assert.True(entries[0].IsWithinGracePeriod);
        }

        [Fact]
        public async Task GetUndoLogEntriesAsync_RespectsRetentionWindow()
        {
            var service = new QuarantineUndoLogService(_fakeQuarantineService, customStoragePath: _testDir);

            await service.RecordQuarantineDecisionAsync(1, @"C:\test1.exe", 90, "Trojan.A", "Chain1");

            // Normal window includes it
            var entries = await service.GetUndoLogEntriesAsync(TimeSpan.FromDays(30));
            Assert.Single(entries);

            // 0-second window excludes past entries
            var expiredEntries = await service.GetUndoLogEntriesAsync(TimeSpan.FromMilliseconds(-100));
            Assert.Empty(expiredEntries);
        }

        [Fact]
        public async Task BulkRestoreAsync_RestoresMultipleItemsAndMarksThemRestored()
        {
            var service = new QuarantineUndoLogService(_fakeQuarantineService, customStoragePath: _testDir);

            await service.RecordQuarantineDecisionAsync(10, @"C:\file1.exe", 90, "Threat1", "Chain1");
            await service.RecordQuarantineDecisionAsync(20, @"C:\file2.exe", 85, "Threat2", "Chain2");

            int restoredCount = await service.BulkRestoreAsync(new[] { 10, 20 });
            Assert.Equal(2, restoredCount);
            Assert.Contains(10, _fakeQuarantineService.RestoredIds);
            Assert.Contains(20, _fakeQuarantineService.RestoredIds);

            // Once restored, they should not show in active undo list
            var activeUndoEntries = await service.GetUndoLogEntriesAsync();
            Assert.Empty(activeUndoEntries);
        }
    }
}
