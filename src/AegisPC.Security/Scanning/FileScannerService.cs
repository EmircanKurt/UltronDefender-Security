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
    public partial class FileScannerService : IFileScanner
    {
        private readonly IDirectoryWalker _directoryWalker;
        private readonly IScanQueueCoordinator _queueCoordinator;
        private readonly IFileHashMatcher _hashMatcher;
        private readonly IPupAnalysisCoordinator _pupCoordinator;
        private readonly ArchiveSafetyScanner _archiveScanner;
        private readonly IFileContentClassifier _contentClassifier;
        private readonly ISecurityFindingService? _findingService;
        private readonly ILogger<FileScannerService>? _logger;

        private readonly object _pauseLock = new();
        private Stopwatch? _activeScanStopwatch;

        public bool IsPaused => _queueCoordinator.IsPaused;
        public IFileHashMatcher HashMatcher => _hashMatcher;

        public static HashSet<string> SafeMediaExtensions => ScanFilterPolicy.SafeMediaExtensions;
        public static HashSet<string> ExcludedDirectoryNames => ScanFilterPolicy.ExcludedDirectoryNames;
        public static bool IsInspectableCandidate(string path) => ScanFilterPolicy.IsInspectableCandidate(path);

        public void PauseScan()
        {
            lock (_pauseLock)
            {
                _activeScanStopwatch?.Stop();
            }
            _queueCoordinator.PauseScan();
        }

        public void ResumeScan()
        {
            lock (_pauseLock)
            {
                _activeScanStopwatch?.Start();
            }
            _queueCoordinator.ResumeScan();
        }

        public static bool IsSelfOwnedPath(string path) => ScanFilterPolicy.IsSelfOwnedPath(path);

        /// <summary>Builds the shared detector pipeline and bounded content classifier; names and signatures never establish clean content alone.</summary>
        public FileScannerService(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IAllowlistService allowlistService,
            ISecurityFindingService? findingService = null,
            IDetectionHub? detectionHub = null,
            ArchiveSafetyScanner? archiveScanner = null,
            IScanResourceManager? resourceManager = null,
            ILogger<FileScannerService>? logger = null,
            IExclusionService? exclusionService = null,
            IFileContentClassifier? contentClassifier = null)
            : this(
                new DirectoryWalker(),
                new ScanQueueCoordinator(resourceManager),
                new FileHashMatcher(hashService, signatureVerifier, allowlistService, exclusionService),
                new PupAnalysisCoordinator(detectionHub ?? DetectionHubFactory.CreateDefault(hashService, signatureVerifier, exclusionService: exclusionService), findingService),
                archiveScanner,
                findingService,
                logger,
                contentClassifier)
        {
        }

        /// <summary>Uses a supplied shared detection hub so manual and real-time providers make the same evidence decisions.</summary>
        public FileScannerService(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IAllowlistService allowlistService,
            IDetectionHub detectionHub,
            ArchiveSafetyScanner? archiveScanner = null,
            ISecurityFindingService? findingService = null,
            IScanResourceManager? resourceManager = null,
            ILogger<FileScannerService>? logger = null,
            IExclusionService? exclusionService = null,
            IFileContentClassifier? contentClassifier = null)
            : this(
                new DirectoryWalker(),
                new ScanQueueCoordinator(resourceManager),
                new FileHashMatcher(hashService, signatureVerifier, allowlistService, exclusionService),
                new PupAnalysisCoordinator(detectionHub, findingService),
                archiveScanner,
                findingService,
                logger,
                contentClassifier)
        {
        }

        /// <summary>Accepts isolated collaborators for traversal, queueing and detector routing without starting live protection.</summary>
        public FileScannerService(
            IDirectoryWalker directoryWalker,
            IScanQueueCoordinator queueCoordinator,
            IFileHashMatcher hashMatcher,
            IPupAnalysisCoordinator pupCoordinator,
            ArchiveSafetyScanner? archiveScanner = null,
            ISecurityFindingService? findingService = null,
            ILogger<FileScannerService>? logger = null,
            IFileContentClassifier? contentClassifier = null)
        {
            _directoryWalker = directoryWalker;
            _queueCoordinator = queueCoordinator;
            _hashMatcher = hashMatcher;
            _pupCoordinator = pupCoordinator;
            _archiveScanner = archiveScanner ?? new ArchiveSafetyScanner();
            _contentClassifier = contentClassifier ?? new FileContentClassifier();
            _findingService = findingService;
            _logger = logger;
        }


        /// <summary>Runs one scan and separately reports lifecycle completion and observed coverage gaps.</summary>
        public async Task<ScanResult> ScanDirectoryAsync(
            string path,
            ScanType scanType,
            IProgress<ScanProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            _hashMatcher.IsScanActive = true;
            _hashMatcher.ResetCounters();
            var stopwatch = Stopwatch.StartNew();
            var coverage = new ScanCoverageSummary();
            var findings = new ConcurrentBag<SecurityFinding>();
            int finalTotal = 0, finalScanned = 0, finalSkipped = 0, finalFailed = 0, finalTimedOut = 0;

            try
            {
                using var coverageScope = (_directoryWalker as IDirectoryCoverageProvider)?.BeginCoverage(coverage);
                using var processTelemetry = new ScanProcessTelemetry(_logger);
                lock (_pauseLock)
                {
                    _activeScanStopwatch = stopwatch;
                }
            var etaEstimator = new ScanEtaEstimator();
            string currentPhase = "Hazırlık";

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

                if (!force)
                {
                    if (lastReport.ElapsedMilliseconds < 100) return;
                    if (!Monitor.TryEnter(progressLock)) return;
                }
                else
                {
                    Monitor.Enter(progressLock);
                }

                try
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

                    var metrics = processTelemetry.Sample();

                    progress.Report(new ScanProgress
                    {
                        ScanType = scanType,
                        Phase = currentPhase,
                        TotalFiles = Math.Max(tot, scn),
                        ScannedFiles = scn,
                        ScannedFromCache = _queueCoordinator.ScannedFromCache,
                        SkippedSignedClean = _queueCoordinator.SkippedSignedClean,
                        NewlyScanned = _queueCoordinator.NewlyScanned,
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
                        CpuUsagePercent = metrics.CpuPercent,
                        IsCpuTelemetryAvailable = metrics.HasCpuSample,
                        RamUsageMb = metrics.WorkingSetMb,
                        PeakObservedRamUsageMb = processTelemetry.PeakObservedWorkingSetMb,
                        ResourceProfileName = ScanQueueCoordinator.ActiveResourceSummary,
                        ActiveWorkers = _queueCoordinator.ActiveWorkers,
                        EffectiveWorkerLimit = _queueCoordinator.EffectiveWorkerLimit,
                        PendingFiles = _queueCoordinator.PendingFiles,
                        IsCompleted = false
                    });
                }
                finally
                {
                    Monitor.Exit(progressLock);
                }
            }

            // STAGE 1: read-only system persistence inspection (not Microsoft MRT).
            if (scanType == ScanType.Full || scanType == ScanType.Quick)
            {
                currentPhase = "Başlangıç kontrolleri";
                var phaseStartedAt = stopwatch.Elapsed;
                int mrtStep = 0;
                var mrtReporter = new Progress<string>(phase =>
                {
                    mrtStep++;
                    int mrtPercent = Math.Min(12, mrtStep * 2);
                    ReportProgress(phase, mrtPercent, force: true);
                });

                var mrtFindings = await SystemPersistenceInspector.ScanAsync(mrtReporter, cancellationToken);
                foreach (var f in mrtFindings)
                {
                    if (f.RiskLevel == RiskLevel.Unknown && f.RiskScore == 0)
                    {
                        coverage.RecordLimitation(f.Description);
                        continue;
                    }
                    findings.Add(f);
                    if (_findingService != null)
                    {
                        await _findingService.AddFindingAsync(f, cancellationToken);
                    }
                }
                _logger?.LogInformation("Initial security checks completed in {ElapsedMs} ms for {ScanType} scan.",
                    (stopwatch.Elapsed - phaseStartedAt).TotalMilliseconds, scanType);
            }

            // STAGE 2: ASYNC FILE STREAMING & DETAILED CONCURRENT SCANNING
            currentPhase = "Dosyalar inceleniyor";
            var filePhaseStartedAt = stopwatch.Elapsed;
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
                async (file, ct) =>
                {
                    var inspected = await ScanFileDetailedAsync(file, TimeSpan.FromSeconds(30), ct);
                    if (inspected.ContentClassification is { IsComplete: false } identity)
                    {
                        foreach (string limitation in identity.CoverageLimitations) coverage.RecordLimitation(limitation);
                        if (identity.RequiresZipInspection) coverage.RecordPartialArchive();
                    }
                    if (inspected.Outcome is FileScanOutcome.Failed or FileScanOutcome.Timeout)
                        coverage.RecordLimitation(inspected.ErrorMessage ?? "FileInspectionIncomplete");
                    return inspected;
                },
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
            _logger?.LogInformation("File queue completed in {ElapsedMs} ms: {Total} total, {Scanned} analyzed, {Failed} failed, {TimedOut} timed out; sampled peak process working set {PeakMb} MiB.",
                (stopwatch.Elapsed - filePhaseStartedAt).TotalMilliseconds, finalTotal, finalScanned, finalFailed, finalTimedOut,
                processTelemetry.PeakObservedWorkingSetMb);

            stopwatch.Stop();
            lock (_pauseLock)
            {
                if (_activeScanStopwatch == stopwatch)
                {
                    _activeScanStopwatch = null;
                }
            }

            var finalMetrics = processTelemetry.Sample();
            if (cancellationToken.IsCancellationRequested)
            {
                progress?.Report(new ScanProgress
                {
                    ScanType = scanType,
                    Phase = "İptal edildi",
                    TotalFiles = Math.Max(finalTotal, finalScanned),
                    ScannedFiles = finalScanned,
                    ScannedFromCache = _queueCoordinator.ScannedFromCache,
                    SkippedSignedClean = _queueCoordinator.SkippedSignedClean,
                    NewlyScanned = _queueCoordinator.NewlyScanned,
                    SkippedFiles = finalSkipped,
                    FailedFiles = finalFailed,
                    TimedOutFiles = finalTimedOut,
                    FindingsCount = findings.Count,
                    CurrentFile = "İptal edildi",
                    ProgressPercent = maxReportedPercent,
                    ElapsedTime = stopwatch.Elapsed,
                    ElapsedSeconds = stopwatch.Elapsed.TotalSeconds,
                    EstimatedRemainingSeconds = 0,
                    FormattedEta = "İptal edildi",
                    EtaConfidence = ConfidenceLevel.High,
                    CpuUsagePercent = finalMetrics.CpuPercent,
                    IsCpuTelemetryAvailable = finalMetrics.HasCpuSample,
                    RamUsageMb = finalMetrics.WorkingSetMb,
                    PeakObservedRamUsageMb = processTelemetry.PeakObservedWorkingSetMb,
                    ResourceProfileName = ScanQueueCoordinator.ActiveResourceSummary,
                    ActiveWorkers = _queueCoordinator.ActiveWorkers,
                    EffectiveWorkerLimit = _queueCoordinator.EffectiveWorkerLimit,
                    PendingFiles = _queueCoordinator.PendingFiles,
                    IsCompleted = false
                });

                return new ScanResult
                {
                    ScanType = scanType,
                    StartedAt = DateTime.UtcNow.Subtract(stopwatch.Elapsed),
                    CompletedAt = DateTime.UtcNow,
                    Status = ScanStatus.Cancelled,
                    TotalFiles = finalTotal,
                    ScannedFiles = finalScanned,
                    SkippedFiles = finalSkipped,
                    FailedFiles = finalFailed,
                    TimedOutFiles = finalTimedOut,
                    CustomPath = path,
                    ElapsedMs = stopwatch.ElapsedMilliseconds,
                    Findings = findings.ToList(),
                    Coverage = coverage
                };
            }

            progress?.Report(new ScanProgress
            {
                ScanType = scanType,
                Phase = "Tamamlandı",
                TotalFiles = Math.Max(finalTotal, finalScanned),
                ScannedFiles = finalScanned,
                ScannedFromCache = _queueCoordinator.ScannedFromCache,
                SkippedSignedClean = _queueCoordinator.SkippedSignedClean,
                NewlyScanned = _queueCoordinator.NewlyScanned,
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
                CpuUsagePercent = finalMetrics.CpuPercent,
                IsCpuTelemetryAvailable = finalMetrics.HasCpuSample,
                RamUsageMb = finalMetrics.WorkingSetMb,
                PeakObservedRamUsageMb = processTelemetry.PeakObservedWorkingSetMb,
                ResourceProfileName = ScanQueueCoordinator.ActiveResourceSummary,
                ActiveWorkers = _queueCoordinator.ActiveWorkers,
                EffectiveWorkerLimit = _queueCoordinator.EffectiveWorkerLimit,
                PendingFiles = _queueCoordinator.PendingFiles,
                IsCompleted = true
            });

            return new ScanResult
            {
                ScanType = scanType,
                StartedAt = DateTime.UtcNow.Subtract(stopwatch.Elapsed),
                CompletedAt = DateTime.UtcNow,
                Status = ScanStatus.Completed,
                TotalFiles = finalTotal,
                ScannedFiles = finalScanned,
                SkippedFiles = finalSkipped,
                FailedFiles = finalFailed,
                TimedOutFiles = finalTimedOut,
                CustomPath = path,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                Findings = findings.ToList(),
                Coverage = coverage
            };
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Directory scanner stopped before producing a terminal result.");
                bool cancelled = ex is OperationCanceledException && cancellationToken.IsCancellationRequested;
                var partial = CreateInterruptedScanResult(path, scanType, stopwatch, coverage, findings,
                    (finalTotal, finalScanned, finalSkipped, finalFailed, finalTimedOut), cancelled);
                if (cancelled) return partial;
                throw new ScanExecutionFailureException(partial, ex);
            }
            finally
            {
                _hashMatcher.IsScanActive = false;
                lock (_pauseLock) { if (_activeScanStopwatch == stopwatch) _activeScanStopwatch = null; }
            }
        }
    }
}
