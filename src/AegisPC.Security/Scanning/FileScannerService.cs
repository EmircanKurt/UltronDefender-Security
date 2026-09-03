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
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Çok iş parçacıklı dosya ve dizin tarama orkestratörü.
    /// Modüler mimaride DirectoryWalker, ScanQueueCoordinator, FileHashMatcher,
    /// PupAnalysisCoordinator ve ArchiveSafetyScanner bileşenlerini koordine eder.
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

        public bool IsPaused => _queueCoordinator.IsPaused;
        public void PauseScan() => _queueCoordinator.PauseScan();
        public void ResumeScan() => _queueCoordinator.ResumeScan();

        public static readonly HashSet<string> KnownCandidateExtensions = ScanFilterPolicy.KnownCandidateExtensions;
        public static readonly HashSet<string> SafeMediaExtensions = ScanFilterPolicy.SafeMediaExtensions;
        public static readonly HashSet<string> ExcludedDirectoryNames = ScanFilterPolicy.ExcludedDirectoryNames;
        public static bool IsSelfOwnedPath(string filePath) => ScanFilterPolicy.IsSelfOwnedPath(filePath);
        public static bool IsInspectableCandidate(string filePath) => ScanFilterPolicy.IsInspectableCandidate(filePath);

        public FileScannerService(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IAllowlistService allowlistService,
            ISecurityFindingService findingService,
            IDetectionHub? detectionHub = null,
            ArchiveSafetyScanner? archiveScanner = null,
            ILogger<FileScannerService>? logger = null)
            : this(
                new DirectoryWalker(),
                new ScanQueueCoordinator(),
                new FileHashMatcher(hashService, signatureVerifier, allowlistService),
                new PupAnalysisCoordinator(
                    detectionHub ?? DetectionHubFactory.CreateDefault(hashService, signatureVerifier),
                    findingService),
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
            if (!File.Exists(path)) return null;

            // SELF-PROTECTION: Uygulamanın kendi imza/veritabanı/log/config dosyalarını asla tarama
            if (IsSelfOwnedPath(path)) return null;

            try
            {
                var fileInfo = new FileInfo(path);
                if (fileInfo.Length == 0 || fileInfo.Length > 100 * 1024 * 1024) return null;

                var ext = fileInfo.Extension.ToLowerInvariant();
                bool isGameDir = PathHelper.IsGameOrRepackDirectory(path) || GameCrackClassifier.IsGameCrackOrEmulator(path);

                // Multi-Tier Caching: Değişmemiş temiz dosyalar için derin dedektör taramasını atla
                if (_hashMatcher.TryGetCached(path, fileInfo, isGameDir, out var cachedFinding))
                {
                    return cachedFinding;
                }

                // 1. Oyun Klasörü Kontrolü — Güvenli oyun modları ve kaynaklarını atla
                if (isGameDir && (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" && ext != ".ps1"))
                {
                    return null;
                }

                // 2. Arşiv Dosyası Güvenlik Taraması (Zip bomb, path traversal, nested payload)
                if (ext is ".zip" or ".jar" or ".nupkg" or ".apk")
                {
                    if (!isGameDir)
                    {
                        var archiveResult = await _archiveScanner.ScanArchiveAsync(path, cancellationToken);
                        if (archiveResult.Findings.Count > 0)
                        {
                            var topFinding = archiveResult.Findings.OrderByDescending(f => f.RiskScore).First();
                            if (_findingService != null)
                            {
                                await _findingService.AddFindingAsync(topFinding, cancellationToken);
                            }
                            _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, topFinding);
                            return topFinding;
                        }
                    }
                }

                // 3. SHA256 Hesaplama & Güvenli Beyaz Liste & Fast-Path WHQL İmza
                var (sha256, isAllowlisted, isMicrosoftBypassed) = await _hashMatcher.EvaluateHashAndAllowlistAsync(path, cancellationToken);
                if (isAllowlisted || isMicrosoftBypassed)
                {
                    _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, null);
                    return null;
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
                        await _findingService.AddFindingAsync(osFinding, cancellationToken);
                    }
                    _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, osFinding);
                    return osFinding;
                }

                // 4. Bütünleşik DetectionHub ve PUP/Risk Eşik Değerlendirmesi
                var finding = await _pupCoordinator.AnalyzeAsync(path, fileInfo, sha256, isGameDir, cancellationToken);
                _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, finding);
                return finding;
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error scanning file {Path}", path);
                return null;
            }
        }

        public async Task<ScanResult> ScanDirectoryAsync(
            string path,
            ScanType scanType,
            IProgress<ScanProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var findings = new ConcurrentBag<SecurityFinding>();

            int maxReportedPercent = 0;
            var lastReport = Stopwatch.StartNew();
            var progressLock = new object();

            void ReportProgress(string currentFile, int? explicitPercent = null, bool force = false, int tot = 0, int scn = 0, int skp = 0)
            {
                if (progress == null) return;

                lock (progressLock)
                {
                    if (!force && lastReport.ElapsedMilliseconds < 120)
                    {
                        return;
                    }
                    lastReport.Restart();

                    int calculatedPercent;
                    if (explicitPercent.HasValue)
                    {
                        calculatedPercent = explicitPercent.Value;
                    }
                    else if (tot > 0 && scn >= tot)
                    {
                        calculatedPercent = 15 + (int)(((double)scn / tot) * 84.0);
                    }
                    else
                    {
                        if (scn == 0)
                        {
                            calculatedPercent = 12;
                        }
                        else
                        {
                            double ratio = (double)scn / Math.Max(tot, scn + 60);
                            calculatedPercent = 12 + (int)(ratio * 48.0);
                        }
                    }

                    calculatedPercent = Math.Clamp(calculatedPercent, 0, 99);
                    int reportedPercent = Math.Max(maxReportedPercent, calculatedPercent);
                    maxReportedPercent = reportedPercent;

                    progress.Report(new ScanProgress
                    {
                        ScanType = scanType,
                        TotalFiles = Math.Max(tot, scn),
                        ScannedFiles = scn,
                        SkippedFiles = skp,
                        FindingsCount = findings.Count,
                        CurrentFile = currentFile,
                        ProgressPercent = reportedPercent,
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

            // STAGE 2: ASYNC FILE STREAMING & CONCURRENT SCANNING
            int finalTotal = 0;
            int finalScanned = 0;
            int finalSkipped = 0;

            var (queueTotal, queueScanned, queueSkipped) = await _queueCoordinator.ExecuteScanQueueAsync(
                path,
                scanType,
                tryQueueFunc => _directoryWalker.WalkDirectoriesForScanTypeAsync(
                    scanType,
                    path,
                    tryQueueFunc,
                    msg => ReportProgress(msg, force: true),
                    cancellationToken,
                    _queueCoordinator.PauseEvent),
                ScanFileAsync,
                findings,
                (curFile, tot, scn, skp) =>
                {
                    finalTotal = tot;
                    finalScanned = scn;
                    finalSkipped = skp;
                    ReportProgress(curFile, null, false, tot, scn, skp);
                },
                cancellationToken);

            finalTotal = queueTotal;
            finalScanned = queueScanned;
            finalSkipped = queueSkipped;

            stopwatch.Stop();

            // Tarama bittiğinde çalışan tüm Gen2/LOH birikimini eksiksiz serbest bırak
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);

            progress?.Report(new ScanProgress
            {
                ScanType = scanType,
                TotalFiles = finalTotal,
                ScannedFiles = finalScanned,
                SkippedFiles = finalSkipped,
                FindingsCount = findings.Count,
                CurrentFile = "Tamamlandı",
                ProgressPercent = 100,
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
                CustomPath = path,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                Findings = findings.ToList()
            };
        }
    }
}
