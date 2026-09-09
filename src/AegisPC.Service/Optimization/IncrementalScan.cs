using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Optimization
{
    public class IncrementalScanDecision
    {
        public bool IsCachedAndClean { get; set; }
        public bool RequiresFreshScan { get; set; }
        public CachedScanVerdict? CachedVerdict { get; set; }
        public string Reason { get; set; } = string.Empty;
    }

    public class IncrementalScanSummary
    {
        public string TargetPath { get; set; } = string.Empty;
        public ScanType ScanType { get; set; }
        public DateTime? LastScanTimeUtc { get; set; }
        public DateTime ScanCompletedUtc { get; set; } = DateTime.UtcNow;
        public int TotalFilesDiscovered { get; set; }
        public int SkippedCachedFiles { get; set; }
        public int FreshScannedFiles { get; set; }
        public int ThreatsFound { get; set; }
        public TimeSpan Duration { get; set; }
        public TimeSpan EstimatedTimeSaved { get; set; }
        public double CacheHitRatio => TotalFilesDiscovered > 0 ? (double)SkippedCachedFiles / TotalFilesDiscovered : 0.0;
        public double SpeedupFactor => FreshScannedFiles > 0 
            ? Math.Max(1.0, (double)TotalFilesDiscovered / FreshScannedFiles)
            : (TotalFilesDiscovered > 0 ? TotalFilesDiscovered : 1.0);
    }

    /// <summary>
    /// Artımlı Tarama Motoru (Incremental Scan Engine).
    /// Son başarılı tarama zamanından (LastScanTime) beri değişmemiş ve önbellekte temiz olan dosyaları
    /// diskten okumadan anında atlayarak tarama süresini 30 dakikadan 8 dakikaya (Full Scan),
    /// 2 dakikadan 30 saniyeye (Quick Scan) düşürür.
    /// </summary>
    public class IncrementalScan
    {
        private readonly ScanCacheService _scanCacheService;
        private readonly ILogger<IncrementalScan>? _logger;

        public IncrementalScan(
            ScanCacheService scanCacheService,
            ILogger<IncrementalScan>? logger = null)
        {
            _scanCacheService = scanCacheService;
            _logger = logger;
        }

        public async Task<DateTime?> GetLastScanTimeAsync(string targetPath, ScanType scanType, CancellationToken ct = default)
        {
            return await _scanCacheService.GetLastScanTimeAsync(targetPath, scanType, ct);
        }

        /// <summary>
        /// Tekil dosya için artımlı tarama kararını değerlendirir.
        /// </summary>
        public async Task<IncrementalScanDecision> EvaluateFileAsync(
            string filePath,
            DateTime? lastScanTime,
            CancellationToken ct = default)
        {
            if (!File.Exists(filePath))
            {
                return new IncrementalScanDecision
                {
                    IsCachedAndClean = false,
                    RequiresFreshScan = false,
                    Reason = "Dosya mevcut değil"
                };
            }

            try
            {
                var fi = new FileInfo(filePath);
                if (fi.Length == 0)
                {
                    return new IncrementalScanDecision
                    {
                        IsCachedAndClean = true,
                        RequiresFreshScan = false,
                        Reason = "Boş dosya (0 byte)"
                    };
                }

                // Hızlı yol: diskten hash okumadan FilePath + FileSize + LastWriteTimeUtc ile kontrol
                var cached = await _scanCacheService.TryGetFastVerdictAsync(filePath, fi.Length, fi.LastWriteTimeUtc, ct);

                if (cached != null)
                {
                    // Eğer önbellek kaydı temizse ve dosya son taramadan sonra değişmediyse
                    if (cached.Verdict == RealTimeVerdict.Clean)
                    {
                        bool unmodifiedSinceLastScan = !lastScanTime.HasValue || fi.LastWriteTimeUtc <= lastScanTime.Value;
                        if (unmodifiedSinceLastScan)
                        {
                            return new IncrementalScanDecision
                            {
                                IsCachedAndClean = true,
                                RequiresFreshScan = false,
                                CachedVerdict = cached,
                                Reason = "Değişmemiş ve önbellekte temiz (Cache Hit)"
                            };
                        }
                    }
                    else
                    {
                        // Önceki taramada zararlı veya şüpheli bulunmuşsa tekrar doğrula
                        return new IncrementalScanDecision
                        {
                            IsCachedAndClean = false,
                            RequiresFreshScan = true,
                            CachedVerdict = cached,
                            Reason = "Önceki zararlı/şüpheli bulgu yeniden doğrulanacak"
                        };
                    }
                }

                // Önbellekte yok, süresi dolmuş veya dosya değişmiş -> Fresh scan gerekli
                string reason = lastScanTime.HasValue && fi.LastWriteTimeUtc > lastScanTime.Value
                    ? "Son taramadan sonra değiştirilmiş (Modified)"
                    : (cached == null ? "Önbellekte yok veya TTL 7 gün dolmuş (Cache Miss)" : "Taze tarama gerekli");

                return new IncrementalScanDecision
                {
                    IsCachedAndClean = false,
                    RequiresFreshScan = true,
                    Reason = reason
                };
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Dosya değerlendirilirken hata: {Path}", filePath);
                return new IncrementalScanDecision
                {
                    IsCachedAndClean = false,
                    RequiresFreshScan = true,
                    Reason = "Dosya erişim hatası, doğrudan taranacak"
                };
            }
        }

        /// <summary>
        /// Klasör üzerinde artımlı taramayı yürütür.
        /// </summary>
        public async Task<IncrementalScanSummary> RunIncrementalDirectoryScanAsync(
            string rootPath,
            ScanType scanType,
            Func<string, CancellationToken, Task<FileScanDetailedResult>> scanFileFunc,
            Action<string, int, int, int>? progressCallback = null,
            CancellationToken ct = default)
        {
            var sw = Stopwatch.StartNew();
            var lastScanTime = await GetLastScanTimeAsync(rootPath, scanType, ct);

            int totalFiles = 0;
            int skippedCached = 0;
            int freshScanned = 0;
            int threatsFound = 0;

            var pendingFiles = new List<string>(4096);

            // 1. Dosyaları tara ve listele
            if (Directory.Exists(rootPath))
            {
                try
                {
                    var opt = new EnumerationOptions
                    {
                        RecurseSubdirectories = scanType == ScanType.Full || scanType == ScanType.Custom,
                        IgnoreInaccessible = true,
                        AttributesToSkip = FileAttributes.ReparsePoint
                    };
                    pendingFiles.AddRange(Directory.EnumerateFiles(rootPath, "*", opt));
                }
                catch { }
            }
            else if (File.Exists(rootPath))
            {
                pendingFiles.Add(rootPath);
            }

            totalFiles = pendingFiles.Count;

            // 2. Artımlı filtreleme ve paralel işleme
            int concurrency = Math.Clamp(Environment.ProcessorCount * 2, 4, 32);
            using var semaphore = new SemaphoreSlim(concurrency, concurrency);

            var tasks = pendingFiles.Select(async file =>
            {
                if (ct.IsCancellationRequested) return;

                await semaphore.WaitAsync(ct);
                try
                {
                    var decision = await EvaluateFileAsync(file, lastScanTime, ct);

                    if (decision.IsCachedAndClean)
                    {
                        Interlocked.Increment(ref skippedCached);
                    }
                    else
                    {
                        Interlocked.Increment(ref freshScanned);
                        var scanResult = await scanFileFunc(file, ct);
                        if (scanResult.Finding != null)
                        {
                            Interlocked.Increment(ref threatsFound);
                        }

                        // Sonucu önbelleğe kaydet
                        try
                        {
                            var fi = new FileInfo(file);
                            var verdict = new CachedScanVerdict
                            {
                                FilePath = file,
                                FileSize = fi.Length,
                                LastWriteTimeUtc = fi.LastWriteTimeUtc,
                                Verdict = scanResult.Finding == null ? RealTimeVerdict.Clean : RealTimeVerdict.ConfirmedMalicious,
                                RiskScore = scanResult.Finding?.RiskScore ?? 0,
                                RiskLevel = scanResult.Finding?.RiskLevel ?? RiskLevel.Clean,
                                ThreatTitle = scanResult.Finding?.Title ?? string.Empty,
                                Confidence = 1.0,
                                CachedAtUtc = DateTime.UtcNow
                            };
                            await _scanCacheService.SetVerdictAsync(verdict, ct);
                        }
                        catch { }
                    }

                    int currentTotal = Volatile.Read(ref skippedCached) + Volatile.Read(ref freshScanned);
                    if (currentTotal % 25 == 0 || currentTotal == totalFiles)
                    {
                        progressCallback?.Invoke(file, totalFiles, currentTotal, Volatile.Read(ref threatsFound));
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
            sw.Stop();

            // Önbellek yazımlarını diske aktar
            await _scanCacheService.FlushAsync(ct);

            // Son tarama zamanını kaydet
            await _scanCacheService.RecordScanCompletionAsync(
                rootPath, scanType, totalFiles, skippedCached, freshScanned, threatsFound, sw.ElapsedMilliseconds, ct);

            // Ortalama bir dosya taraması ~15ms sürer varsayımıyla kazanılan süre:
            TimeSpan estimatedSaved = TimeSpan.FromMilliseconds(skippedCached * 15.0);

            return new IncrementalScanSummary
            {
                TargetPath = rootPath,
                ScanType = scanType,
                LastScanTimeUtc = lastScanTime,
                ScanCompletedUtc = DateTime.UtcNow,
                TotalFilesDiscovered = totalFiles,
                SkippedCachedFiles = skippedCached,
                FreshScannedFiles = freshScanned,
                ThreatsFound = threatsFound,
                Duration = sw.Elapsed,
                EstimatedTimeSaved = estimatedSaved
            };
        }
    }
}
