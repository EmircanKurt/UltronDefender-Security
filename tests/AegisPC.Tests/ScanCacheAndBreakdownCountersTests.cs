using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class ScanCacheAndBreakdownCountersTests : IDisposable
    {
        private readonly string _testSandbox;

        public ScanCacheAndBreakdownCountersTests()
        {
            _testSandbox = Path.Combine(Path.GetTempPath(), $"AegisPC_CacheTests_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_testSandbox);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandbox))
                {
                    Directory.Delete(_testSandbox, recursive: true);
                }
            }
            catch
            {
                // Test cleanup
            }
        }

        [Fact]
        public void Test_FileHashMatcher_ClearCache_EmptiesCache_And_TryGetCachedReturnsFalse()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var matcher = new FileHashMatcher(hashService, sigVerifier, allowlist);

            string testFile = Path.Combine(_testSandbox, "dummy.dll");
            File.WriteAllText(testFile, "test-binary-content");
            var fi = new FileInfo(testFile);

            // 1. Doldur: Cache'e bir girdi ekle
            matcher.SetCache(testFile, fi.Length, fi.LastWriteTimeUtc, null);

            // 2. Doğrula: Önbellek isabeti true dönmeli
            bool hitBefore = matcher.TryGetCached(testFile, fi, false, out var findingBefore);
            Assert.True(hitBefore, "SetCache sonrasında TryGetCached true dönmelidir.");
            Assert.Null(findingBefore);
            Assert.True(matcher.CachedEntriesCount > 0, "CachedEntriesCount 0'dan büyük olmalıdır.");

            // 3. Temizle: ClearCache() çağır
            matcher.ClearCache();

            // 4. Doğrula: Cache boşalmış olmalı, TryGetCached false dönmeli
            bool hitAfter = matcher.TryGetCached(testFile, fi, false, out _);
            Assert.False(hitAfter, "ClearCache sonrasında TryGetCached false dönmelidir.");
            Assert.Equal(0, matcher.CachedEntriesCount);
        }

        [Fact]
        public void Test_FileHashMatcher_ClearCache_WhenScanActive_RejectsOperationAndKeepsCache()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var matcher = new FileHashMatcher(hashService, sigVerifier, allowlist);

            string testFile = Path.Combine(_testSandbox, "active_scan_test.dll");
            File.WriteAllText(testFile, "active-scan-content");
            var fi = new FileInfo(testFile);

            matcher.SetCache(testFile, fi.Length, fi.LastWriteTimeUtc, null);
            Assert.True(matcher.TryGetCached(testFile, fi, false, out _));

            // Aktif tarama bayrağını etkinleştir
            matcher.IsScanActive = true;

            // ClearCache çağrısı reddedilmeli
            matcher.ClearCache();

            // Önbellek silinmemiş olmalı
            bool hitWhileScanning = matcher.TryGetCached(testFile, fi, false, out _);
            Assert.True(hitWhileScanning, "Aktif tarama varken ClearCache işlemi reddedilmeli ve önbellek korunmalıdır.");
            Assert.True(matcher.CachedEntriesCount > 0);

            // Tarama bittiğinde temizleme başarılı olmalı
            matcher.IsScanActive = false;
            matcher.ClearCache();

            Assert.False(matcher.TryGetCached(testFile, fi, false, out _));
            Assert.Equal(0, matcher.CachedEntriesCount);
        }

        [Fact]
        public void Test_FileHashMatcher_Tracks_BreakdownCounters_Accurately()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var matcher = new FileHashMatcher(hashService, sigVerifier, allowlist);

            matcher.ResetCounters();
            Assert.Equal(0, matcher.ScannedFromCache);
            Assert.Equal(0, matcher.SkippedSignedClean);
            Assert.Equal(0, matcher.NewlyScanned);

            string testFile = Path.Combine(_testSandbox, "counter_test.exe");
            File.WriteAllText(testFile, "counter-test-data");
            var fi = new FileInfo(testFile);

            // 1. Önce cache'e yaz
            matcher.SetCache(testFile, fi.Length, fi.LastWriteTimeUtc, null);

            // 2. TryGetCached çağrısı -> ScannedFromCache artmalı
            matcher.TryGetCached(testFile, fi, false, out _);
            Assert.Equal(1, matcher.ScannedFromCache);

            // 3. Reset
            matcher.ResetCounters();
            Assert.Equal(0, matcher.ScannedFromCache);
        }

        [Fact]
        public void Test_ScanProgress_BreakdownCounters_SumEqualsScannedFiles()
        {
            var progress = new ScanProgress
            {
                TotalFiles = 100_000,
                ScannedFromCache = 82_331,
                SkippedSignedClean = 3_900,
                NewlyScanned = 9_170
            };
            progress.ScannedFiles = progress.ScannedFromCache + progress.SkippedSignedClean + progress.NewlyScanned;

            // GÖREV 2 Kural 4 Testi: üç sayacın toplamı = ScannedFiles olmalı
            Assert.Equal(95_401, progress.ScannedFiles);
            Assert.Equal(progress.ScannedFiles, progress.ScannedFromCache + progress.SkippedSignedClean + progress.NewlyScanned);
        }

        [Fact]
        public async Task Test_ScanQueueCoordinator_BreakdownCounters_SumEqualsScannedFiles()
        {
            using var coordinator = new ScanQueueCoordinator();

            string f1 = Path.Combine(_testSandbox, "file1.bin");
            string f2 = Path.Combine(_testSandbox, "file2.bin");
            string f3 = Path.Combine(_testSandbox, "file3.bin");
            await File.WriteAllTextAsync(f1, "f1");
            await File.WriteAllTextAsync(f2, "f2");
            await File.WriteAllTextAsync(f3, "f3");

            var findings = new ConcurrentBag<SecurityFinding>();

            var result = await coordinator.ExecuteScanQueueDetailedAsync(
                _testSandbox,
                ScanType.Custom,
                async queueFunc =>
                {
                    await queueFunc(f1);
                    await queueFunc(f2);
                    await queueFunc(f3);
                },
                (path, ct) =>
                {
                    if (path == f1)
                    {
                        // 1. Dosya: Önbellekten geldi
                        return Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero, isFromCache: true));
                    }
                    if (path == f2)
                    {
                        // 2. Dosya: İmzalı temiz geçti
                        return Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero, isSignedClean: true));
                    }
                    // 3. Dosya: Yeni tarandı
                    return Task.FromResult(FileScanDetailedResult.CreateSuccess(path, null, TimeSpan.Zero, isFromCache: false, isSignedClean: false));
                },
                findings,
                (file, tot, scn, skp, fail, tout) => { },
                CancellationToken.None);

            Assert.Equal(3, result.ScannedFiles);
            Assert.Equal(1, coordinator.ScannedFromCache);
            Assert.Equal(1, coordinator.SkippedSignedClean);
            Assert.Equal(1, coordinator.NewlyScanned);

            // Kural: Üç sayacın toplamı = ScannedFiles
            int sum = coordinator.ScannedFromCache + coordinator.SkippedSignedClean + coordinator.NewlyScanned;
            Assert.Equal(result.ScannedFiles, sum);
        }

        [Fact]
        public void Test_SettingsViewModel_ClearScanCacheCommand_ClearsCache_And_LogsToast()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var matcher = new FileHashMatcher(hashService, sigVerifier, allowlist);

            string dummyFile = Path.Combine(_testSandbox, "cached_settings.dll");
            File.WriteAllText(dummyFile, "dummy");
            var fi = new FileInfo(dummyFile);
            matcher.SetCache(dummyFile, fi.Length, fi.LastWriteTimeUtc, null);
            Assert.True(matcher.CachedEntriesCount > 0);

            var toastMock = new MockToastNotificationService();
            var vm = new SettingsViewModel(
                fileHashMatcher: matcher,
                toastNotificationService: toastMock);

            // Act: Butona tıkla
            vm.ClearScanCacheCommand.Execute(null);

            // Assert: Önbellek boşalmış olmalı
            Assert.Equal(0, matcher.CachedEntriesCount);
            Assert.True(toastMock.LastToastTitle.Contains("Önbellek") || toastMock.LastToastMessage.Contains("temizlendi"));
            Assert.Contains("önbellek kaydı temizlendi", toastMock.LastToastMessage);
        }

        [Fact]
        public void Test_SettingsViewModel_ClearScanCacheCommand_WhenScanning_RejectsClear()
        {
            var hashService = new HashService();
            var sigVerifier = new SignatureVerifier();
            var allowlist = new AllowlistService(hashService);
            var matcher = new FileHashMatcher(hashService, sigVerifier, allowlist);

            string dummyFile = Path.Combine(_testSandbox, "cached_settings_scan.dll");
            File.WriteAllText(dummyFile, "dummy");
            var fi = new FileInfo(dummyFile);
            matcher.SetCache(dummyFile, fi.Length, fi.LastWriteTimeUtc, null);

            var toastMock = new MockToastNotificationService();
            var vm = new SettingsViewModel(
                fileHashMatcher: matcher,
                toastNotificationService: toastMock);

            // Simüle et: Tarama aktif
            matcher.IsScanActive = true;

            vm.ClearScanCacheCommand.Execute(null);

            // Önbellek silinmemeli
            Assert.True(matcher.CachedEntriesCount > 0);
            Assert.True(toastMock.LastToastType == "Warning" || toastMock.LastToastTitle.Contains("Reddedildi") || toastMock.LastToastMessage.Contains("Aktif"));
        }

        private class MockToastNotificationService : IWindowsToastNotificationService
        {
            public string LastToastTitle { get; private set; } = string.Empty;
            public string LastToastMessage { get; private set; } = string.Empty;
            public string LastToastType { get; private set; } = string.Empty;

            public void ShowToast(string title, string message, string type = "Info")
            {
                LastToastTitle = title;
                LastToastMessage = message;
                LastToastType = type;
            }
        }
    }
}
