using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Safety;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Ultron Defender yüksek başarımlı dosya ve dizin tarama motoru.
    /// Modüler mimaride DirectoryWalker, ScanQueueCoordinator, FileHashMatcher,
    /// PupAnalysisCoordinator, ScanEtaEstimator ve per-file timeout koruması ile çalışır.
    /// </summary>
    public class FileScannerService : IFileScanner
    {
        private readonly IDirectoryWalker _directoryWalker;
        private readonly IScanQueueCoordinator _queueCoordinator;
        private readonly IFileHashMatcher _hashMatcher;
        private readonly IPupAnalysisCoordinator _pupCoordinator;
        private readonly ArchiveSafetyScanner _archiveScanner;
        private readonly ISecurityFindingService? _findingService;
        private readonly ILogger<FileScannerService>? _logger;

        private readonly object _pauseLock = new();
        private Stopwatch? _activeScanStopwatch;

        public bool IsPaused => _queueCoordinator.IsPaused;
        public IFileHashMatcher HashMatcher => _hashMatcher;

        public static HashSet<string> SafeMediaExtensions => ScanFilterPolicy.SafeMediaExtensions;
        public static HashSet<string> ExcludedDirectoryNames => ScanFilterPolicy.ExcludedDirectoryNames;
        public static bool IsInspectableCandidate(string path) => ScanFilterPolicy.IsInspectableCandidate(path);

        public void PauseScan() => _queueCoordinator.PauseScan();
        public void ResumeScan() => _queueCoordinator.ResumeScan();

        public static bool IsSelfOwnedPath(string path) => ScanFilterPolicy.IsSelfOwnedPath(path);

        public FileScannerService(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IAllowlistService allowlistService,
            ISecurityFindingService? findingService = null,
            IDetectionHub? detectionHub = null,
            ArchiveSafetyScanner? archiveScanner = null,
            IScanResourceManager? resourceManager = null,
            ILogger<FileScannerService>? logger = null)
            : this(
                new DirectoryWalker(),
                new ScanQueueCoordinator(resourceManager),
                new FileHashMatcher(hashService, signatureVerifier, allowlistService),
                new PupAnalysisCoordinator(detectionHub ?? DetectionHubFactory.CreateDefault(hashService, signatureVerifier), findingService),
                archiveScanner,
                findingService,
                logger)
        {
        }

        public FileScannerService(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IAllowlistService allowlistService,
            IDetectionHub detectionHub,
            ArchiveSafetyScanner? archiveScanner = null,
            ISecurityFindingService? findingService = null,
            IScanResourceManager? resourceManager = null,
            ILogger<FileScannerService>? logger = null)
            : this(
                new DirectoryWalker(),
                new ScanQueueCoordinator(resourceManager),
                new FileHashMatcher(hashService, signatureVerifier, allowlistService),
                new PupAnalysisCoordinator(detectionHub, findingService),
                archiveScanner,
                findingService,
                logger)
        {
        }

        public FileScannerService(
            IDirectoryWalker directoryWalker,
            IScanQueueCoordinator queueCoordinator,
            IFileHashMatcher hashMatcher,
            IPupAnalysisCoordinator pupCoordinator,
            ArchiveSafetyScanner? archiveScanner = null,
            ISecurityFindingService? findingService = null,
            ILogger<FileScannerService>? logger = null)
        {
            _directoryWalker = directoryWalker;
            _queueCoordinator = queueCoordinator;
            _hashMatcher = hashMatcher;
            _pupCoordinator = pupCoordinator;
            _archiveScanner = archiveScanner ?? new ArchiveSafetyScanner();
            _findingService = findingService;
            _logger = logger;
        }

        public async Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default)
        {
            var detailed = await ScanFileDetailedAsync(path, TimeSpan.FromSeconds(10), cancellationToken);
            return detailed.Finding;
        }

        public async Task<FileScanDetailedResult> ScanFileDetailedAsync(
            string path,
            TimeSpan perFileTimeout,
            CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();
            if (!File.Exists(path))
            {
                return FileScanDetailedResult.CreateSkipped(path, "Dosya mevcut değil");
            }

            // SELF-PROTECTION: Uygulamanın kendi imza/veritabanı/log/config dosyalarını asla tarama
            if (IsSelfOwnedPath(path))
            {
                return FileScanDetailedResult.CreateSkipped(path, "AegisPC kendi dosyası");
            }

            // Per-file timeout koruması: Kilitli dosya veya askıda kalan işlem tüm taramayı donduramaz
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linkedCts.CancelAfter(perFileTimeout);

            try
            {
                var fileInfo = new FileInfo(path);
                if (fileInfo.Length == 0)
                {
                    return FileScanDetailedResult.CreateSkipped(path, "Boş dosya");
                }

                var ext = fileInfo.Extension.ToLowerInvariant();

                // Multi-Tier Caching: Değişmemiş temiz dosyalar için derin dedektör taramasını atla
                if (_hashMatcher.TryGetCached(path, fileInfo, false, out var cachedFinding))
                {
                    if (cachedFinding == null || cachedFinding.Status == FindingStatus.Resolved || cachedFinding.IsAllowlisted)
                    {
                        return FileScanDetailedResult.CreateSuccess(path, null, sw.Elapsed);
                    }
                    return FileScanDetailedResult.CreateSuccess(path, cachedFinding, sw.Elapsed);
                }

                // 1. SHA256 Hesaplama & Güvenli Beyaz Liste / Çözüldü & Fast-Path WHQL İmza
                var (sha256, isAllowlisted, isMicrosoftBypassed) = await _hashMatcher.EvaluateHashAndAllowlistAsync(path, linkedCts.Token);
                if (isAllowlisted || isMicrosoftBypassed)
                {
                    fileInfo.Refresh();
                    _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, null);
                    return FileScanDetailedResult.CreateSuccess(path, null, sw.Elapsed);
                }

                // 2. Arşiv Dosyası Güvenlik Taraması (Zip bomb, path traversal, nested payload)
                // Kural 27 gereğince: Yol güveni tamamen kaldırıldı (isGameDir = false)
                if (ext is ".zip" or ".jar" or ".nupkg" or ".apk")
                {
                    var archiveResult = await _archiveScanner.ScanArchiveAsync(path, linkedCts.Token);
                    if (archiveResult.Findings.Count > 0)
                    {
                        var topFinding = archiveResult.Findings.OrderByDescending(f => f.RiskScore).First();
                        if (topFinding.Status != FindingStatus.Resolved && !topFinding.IsAllowlisted)
                        {
                            if (_findingService != null)
                            {
                                await _findingService.AddFindingAsync(topFinding, linkedCts.Token);
                            }
                            fileInfo.Refresh();
                            _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, topFinding);
                            return FileScanDetailedResult.CreateSuccess(path, topFinding, sw.Elapsed);
                        }
                    }
                }

                if (sha256 == "VIRUS_INFECTED_OS_BLOCKED")
                {
                    var osFinding = new SecurityFinding
                    {
                        ObjectPath = path,
                        ObjectName = fileInfo.Name,
                        RiskLevel = RiskLevel.ConfirmedMalicious,
                        RiskScore = 100,
                        Category = FindingCategory.KnownMalwareHash,
                        Title = $"🚨 Zararlı Yazılım / EICAR: {fileInfo.Name}",
                        Description = "Dosya işletim sistemi çekirdeği tarafından virüslü olduğu gerekçesiyle kilitlendi (ERROR_VIRUS_INFECTED).",
                        ConfidenceLevel = ConfidenceLevel.High,
                        FirstObserved = DateTime.UtcNow,
                        LastObserved = DateTime.UtcNow,
                        Status = FindingStatus.Active
                    };
                    if (_findingService != null)
                    {
                        await _findingService.AddFindingAsync(osFinding, linkedCts.Token);
                    }
                    fileInfo.Refresh();
                    _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, osFinding);
                    return FileScanDetailedResult.CreateSuccess(path, osFinding, sw.Elapsed);
                }

                // 3. Bütünleşik DetectionHub ve PUP/Risk Eşik Değerlendirmesi
                // Kural 27: Yol indirimleri kaldırıldı (isGameDir = false)
                var finding = await _pupCoordinator.AnalyzeAsync(path, fileInfo, sha256, false, linkedCts.Token);
                if (finding != null && (finding.Status == FindingStatus.Resolved || finding.IsAllowlisted))
                {
                    finding = null;
                }
                fileInfo.Refresh();
                _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, finding);
                return FileScanDetailedResult.CreateSuccess(path, finding, sw.Elapsed);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Tekil dosya per-file timeout'a uğradı
                _logger?.LogWarning("Per-file scan timed out for {Path} after {Timeout}s", path, perFileTimeout.TotalSeconds);
                return FileScanDetailedResult.CreateTimeout(path, sw.Elapsed);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error scanning file {Path}", path);
                return FileScanDetailedResult.CreateFailed(path, ex.Message, sw.Elapsed);
            }
        }

        public async Task<ScanResult> ScanDirectoryAsync(
            string path,
            ScanType scanType,
            IProgress<ScanProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            lock (_pauseLock)
            {
                _activeScanStopwatch = stopwatch;
            }
            var findings = new ConcurrentBag<SecurityFinding>();
            var etaEstimator = new ScanEtaEstimator();

            int maxReportedPercent = 0;
            var lastReport = Stopwatch.StartNew();
            var progressLock = new object();

            void ReportProgress(
                string currentFile,
                int? explicitPercent = null,
                bool force = false,
                int tot = 0,
                int scn = 0,
                int skp = 0,
                int fail = 0,
                int tout = 0)
            {
                if (progress == null) return;

                lock (progressLock)
                {
                    if (!force && lastReport.ElapsedMilliseconds < 100)
                    {
                        return;
                    }
                    lastReport.Restart();

                    double elapsedSec = stopwatch.Elapsed.TotalSeconds;

                    // İstatistiksel EWMA ETA hesabı
                    var (remainingSeconds, confidence, formattedEta) = etaEstimator.Update(tot, scn);

                    // ProgressPercent hesaplaması: total > 0 ise gerçek oran (scanned/total * 100)
                    int calculatedPercent;
                    if (explicitPercent.HasValue)
                    {
                        calculatedPercent = explicitPercent.Value;
                    }
                    else if (tot > 0)
                    {
                        calculatedPercent = (int)Math.Clamp(((double)scn / tot) * 100.0, 0, 99);
                    }
                    else
                    {
                        if (scn == 0)
                        {
                            calculatedPercent = 0;
                        }
                        else
                        {
                            double ratio = (double)scn / Math.Max(tot, scn + 60);
                            calculatedPercent = (int)(ratio * 80.0);
                        }
                    }

                    calculatedPercent = Math.Clamp(calculatedPercent, 0, 99);
                    int reportedPercent = Math.Max(maxReportedPercent, calculatedPercent);
                    maxReportedPercent = reportedPercent;

                    // Canlı bellek kullanımı
                    double ramMb = GC.GetTotalMemory(false) / (1024.0 * 1024.0);

                    progress.Report(new ScanProgress
                    {
                        ScanType = scanType,
                        TotalFiles = Math.Max(tot, scn),
                        ScannedFiles = scn,
                        SkippedFiles = skp,
                        FailedFiles = fail,
                        TimedOutFiles = tout,
                        FindingsCount = findings.Count,
                        CurrentFile = currentFile,
                        ProgressPercent = reportedPercent,
                        ElapsedTime = stopwatch.Elapsed,
                        ElapsedSeconds = elapsedSec,
                        EstimatedRemainingSeconds = remainingSeconds,
                        EtaConfidence = confidence,
                        FormattedEta = formattedEta,
                        RamUsageMb = ramMb,
                        IsCompleted = false
                    });
                }
            }

            // STAGE 1: MICROSOFT MRT (MSRT) REMEDIATION SCAN (0% - 12%)
            if (scanType == ScanType.Full || scanType == ScanType.Quick)
            {
                int mrtStep = 0;
                var mrtReporter = new Progress<string>(phase =>
                {
                    mrtStep++;
                    int mrtPercent = Math.Min(12, mrtStep * 2);
                    ReportProgress(phase, mrtPercent, force: true);
                });

                var mrtFindings = await MsrtRemediationEngine.RunMsrtDeepScanAsync(mrtReporter, cancellationToken);
                foreach (var f in mrtFindings)
                {
                    findings.Add(f);
                    if (_findingService != null)
                    {
                        await _findingService.AddFindingAsync(f, cancellationToken);
                    }
                }
            }

            // STAGE 2: ASYNC FILE STREAMING & DETAILED CONCURRENT SCANNING
            int finalTotal = 0;
            int finalScanned = 0;
            int finalSkipped = 0;
            int finalFailed = 0;
            int finalTimedOut = 0;

            var (queueTotal, queueScanned, queueSkipped, queueFailed, queueTimedOut) = await _queueCoordinator.ExecuteScanQueueDetailedAsync(
                path,
                scanType,
                tryQueueFunc => _directoryWalker.WalkDirectoriesForScanTypeAsync(
                    scanType,
                    path,
                    tryQueueFunc,
                    msg => ReportProgress(msg, force: true),
                    cancellationToken,
                    _queueCoordinator.PauseEvent),
                (file, ct) => ScanFileDetailedAsync(file, TimeSpan.FromSeconds(30), ct),
                findings,
                (curFile, tot, scn, skp, fail, tout) =>
                {
                    finalTotal = tot;
                    finalScanned = scn;
                    finalSkipped = skp;
                    finalFailed = fail;
                    finalTimedOut = tout;
                    ReportProgress(curFile, null, false, tot, scn, skp, fail, tout);
                },
                cancellationToken);

            finalTotal = queueTotal;
            finalScanned = queueScanned;
            finalSkipped = queueSkipped;
            finalFailed = queueFailed;
            finalTimedOut = queueTimedOut;

            stopwatch.Stop();
            lock (_pauseLock)
            {
                if (_activeScanStopwatch == stopwatch)
                {
                    _activeScanStopwatch = null;
                }
            }

            progress?.Report(new ScanProgress
            {
                ScanType = scanType,
                TotalFiles = finalTotal,
                ScannedFiles = finalScanned,
                SkippedFiles = finalSkipped,
                FailedFiles = finalFailed,
                TimedOutFiles = finalTimedOut,
                FindingsCount = findings.Count,
                CurrentFile = "Tamamlandı",
                ProgressPercent = 100,
                ElapsedTime = stopwatch.Elapsed,
                ElapsedSeconds = stopwatch.Elapsed.TotalSeconds,
                EstimatedRemainingSeconds = 0,
                FormattedEta = "Tamamlandı",
                EtaConfidence = ConfidenceLevel.High,
                IsCompleted = true
            });

            return new ScanResult
            {
                ScanType = scanType,
                StartedAt = DateTime.UtcNow.Subtract(stopwatch.Elapsed),
                CompletedAt = DateTime.UtcNow,
                Status = cancellationToken.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed,
                TotalFiles = finalTotal,
                ScannedFiles = finalScanned,
                SkippedFiles = finalSkipped,
                FailedFiles = finalFailed,
                TimedOutFiles = finalTimedOut,
                CustomPath = path,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                Findings = findings.ToList()
            };
        }
    }
}
