using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı, çok aşamalı (Progressive Analysis), olay kararlılığı (Stability Check) doğrulamalı,
    /// sıfır sahte veri (Zero-Mock) içeren Windows Endpoint Real-Time Protection Ana Orkestratörü.
    /// Modüler mimaride Ingestor, StabilityChecker, VerdictProcessor ve PolicyEnforcer bileşenlerini koordine eder.
    /// </summary>
    public partial class RealTimeProtectionEngine : IRealTimeProtectionEngine, IDisposable
    {
        private readonly IRealTimeEventIngestor _eventIngestor;
        private readonly IRealTimeStabilityChecker _stabilityChecker;
        private readonly IRealTimeVerdictProcessor _verdictProcessor;
        private readonly IRealTimePolicyEnforcer _policyEnforcer;
        private readonly ILogger<RealTimeProtectionEngine>? _logger;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly List<string> _watchedLocationsList = new();
        private CancellationTokenSource? _engineCts;
        private ManagementEventWatcher? _usbArrivalWatcher;
        private volatile bool _isRunning;
        private readonly object _lock = new();
        private Timer? _cacheCleanupTimer;
        private bool _coverageDegraded;
        private long _engineGeneration;

        public bool IsRunning => _isRunning;

        public event Action<SecurityFinding>? OnThreatDetected;
        public event Action<SecurityIncident>? OnIncidentCreated;
        public event Action<string, string, string>? OnNotificationRaised;
        public event Action<RealTimeActivityEvent>? OnActivityLogged;
        public event Action<bool, string>? OnProtectionHealthChanged;

        public RealTimeProtectionEngine(
            IFileScanner fileScanner,
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IQuarantineService quarantineService,
            ISecurityFindingService findingService,
            IAuditLogService? auditLogService = null,
            IReputationService? reputationService = null,
            ILogger<RealTimeProtectionEngine>? logger = null,
            IExclusionService? exclusionService = null,
            Func<bool>? enableAutoQuarantine = null,
            Func<int>? autoQuarantineThreshold = null,
            IDetectionHub? detectionHub = null)
            : this(
                new RealTimeEventIngestor(),
                new RealTimeStabilityChecker(),
                new RealTimeVerdictProcessor(hashService, signatureVerifier, riskScoringEngine, (fileScanner as AegisPC.Security.Scanning.FileScannerService)?.HashMatcher, reputationService, exclusionService, logger, detectionHub),
                new RealTimePolicyEnforcer(quarantineService, findingService, auditLogService, logger,
                    enableAutoQuarantine, autoQuarantineThreshold),
                logger)
        {
        }

        public RealTimeProtectionEngine(
            IRealTimeEventIngestor eventIngestor,
            IRealTimeStabilityChecker stabilityChecker,
            IRealTimeVerdictProcessor verdictProcessor,
            IRealTimePolicyEnforcer policyEnforcer,
            ILogger<RealTimeProtectionEngine>? logger = null)
        {
            _eventIngestor = eventIngestor;
            _stabilityChecker = stabilityChecker;
            _verdictProcessor = verdictProcessor;
            _policyEnforcer = policyEnforcer;
            _logger = logger;
            if (_eventIngestor is RealTimeEventIngestor arrivals)
                arrivals.OnReconciliationRequired += RequestReconciliation;

            // Policy enforcer olaylarını ana motora bağla
            _policyEnforcer.OnThreatDetected += finding => OnThreatDetected?.Invoke(finding);
            _policyEnforcer.OnIncidentCreated += incident => OnIncidentCreated?.Invoke(incident);
            _policyEnforcer.OnNotificationRaised += (title, msg, sev) => OnNotificationRaised?.Invoke(title, msg, sev);
        }

        public void Start() => Start(watchDefaultLocations: true);

        public void Start(bool watchDefaultLocations = true)
        {
            lock (_lock)
            {
                if (_isRunning) return;
                _isRunning = true;
                _coverageDegraded = false;
                _engineGeneration++;
                _engineCts = new CancellationTokenSource();

                // 1. Setup Watchers on Critical Directories
                if (watchDefaultLocations)
                {
                    SetupFileSystemWatchers();
                }

                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = true; }
                    catch (Exception ex)
                    {
                        _coverageDegraded = true;
                        _logger?.LogWarning(ex, "Could not enable file-arrival watcher {Path}", w.Path);
                    }
                }

                // 2. Start Background Multi-Worker Pool Consumers
                int workerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
                _eventIngestor.StartWorkers(workerCount, HandleNormalizedEventAsync, _engineCts.Token);

                // 3. Start WMI Dynamic Removable Media / USB Listener
                if (watchDefaultLocations) StartUsbArrivalListener();

                _cacheCleanupTimer = new Timer(_ =>
                {
                    try { _verdictProcessor.CleanupCache(); }
                    catch (Exception ex) { _logger?.LogWarning(ex, "Real-time cache maintenance failed"); }
                }, null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));

                _logger?.LogInformation("Ultron Defender Real-Time Protection Engine started successfully with {Workers} workers.", workerCount);
                bool covered = !_coverageDegraded && _watchers.Count > 0;
                OnProtectionHealthChanged?.Invoke(covered, covered
                    ? "Kullanıcı modu dosya geliş izleme etkin; yalnız listelenen dizinler kapsanıyor"
                    : "Motor etkin; izleme kapsamı eksik veya henüz dizin seçilmedi");
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;
                _isRunning = false;
                _engineGeneration++;
                _reconciliationRoots.Clear();
                _reconciliationRunning = false;

                StopUsbArrivalListener();

                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = false; w.Dispose(); }
                    catch (Exception ex) { _logger?.LogWarning(ex, "Failed disposing file-arrival watcher {Path}", w.Path); }
                }
                _watchers.Clear();
                _watchedLocationsList.Clear();

                _engineCts?.Cancel();
                _engineCts?.Dispose();
                _engineCts = null;

                _eventIngestor.Stop();

                _cacheCleanupTimer?.Dispose();
                _cacheCleanupTimer = null;

                _logger?.LogInformation("Ultron Defender Real-Time Protection Engine stopped.");
                OnProtectionHealthChanged?.Invoke(false, "Durduruldu");
            }
        }

        /// <summary>
        /// Watcher'lardan gelen olayları Ingestor kuyruğuna delege eder.
        /// </summary>
        private void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null)
        {
            _eventIngestor.EnqueueEvent(type, path, oldPath);
        }

        /// <summary>
        /// Belirtilen dosyayı çok aşamalı (Hash, İmza, Entropi, PE, Sezgisel) olarak denetler.
        /// </summary>
        public Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default)
        {
            return _verdictProcessor.InspectFileAsync(filePath, ct);
        }

        private async Task HandleNormalizedEventAsync(NormalizedFileEvent evt, CancellationToken ct)
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                if (Directory.Exists(evt.NormalizedPath))
                {
                    if (evt.EventType is RealTimeEventType.Created or RealTimeEventType.Renamed)
                        RequestDirectoryInspection(evt.NormalizedPath);
                    return;
                }
                var fileName = Path.GetFileName(evt.NormalizedPath);

                // Stage 1: Event Captured Telemetry
                OnActivityLogged?.Invoke(new RealTimeActivityEvent
                {
                    CorrelationId = evt.CorrelationId,
                    FileName = fileName,
                    FilePath = evt.NormalizedPath,
                    Stage = "FILE_DETECTED",
                    Message = $"Dosya hareketi algılandı ({evt.EventType})",
                    Severity = "Info",
                    Timestamp = DateTime.Now
                });

                // Stage 2: Wait for file write stability (file download or write completion)
                OnActivityLogged?.Invoke(new RealTimeActivityEvent
                {
                    CorrelationId = evt.CorrelationId,
                    FileName = fileName,
                    FilePath = evt.NormalizedPath,
                    Stage = "STABILITY_CHECK",
                    Message = "Dosya stabilite ve yazma kilidi kontrol ediliyor...",
                    Severity = "Info",
                    Timestamp = DateTime.Now
                });

                bool isStable = await _stabilityChecker.WaitForFileStabilityAsync(evt.NormalizedPath, ct);
                if (!isStable || !File.Exists(evt.NormalizedPath)) return;

                // Stage 3: Progressive Instant Arrival Inspection
                OnActivityLogged?.Invoke(new RealTimeActivityEvent
                {
                    CorrelationId = evt.CorrelationId,
                    FileName = fileName,
                    FilePath = evt.NormalizedPath,
                    Stage = "SCAN_STARTED",
                    Message = "Progresif güvenlik taraması başlatıldı (Hash, İmza, PE, Sezgiseller)...",
                    Severity = "Info",
                    Timestamp = DateTime.Now
                });

                var verdict = await _verdictProcessor.InspectFileAsync(evt.NormalizedPath, ct);
                verdict.EventTime = evt.Timestamp;

                // Stage 4: Verdict Telemetry
                OnActivityLogged?.Invoke(new RealTimeActivityEvent
                {
                    CorrelationId = evt.CorrelationId,
                    FileName = fileName,
                    FilePath = evt.NormalizedPath,
                    Stage = "VERDICT",
                    RiskScore = verdict.RiskScore,
                    Verdict = verdict.Verdict.ToString(),
                    TimeToDetectMs = verdict.TimeToDetectMs,
                    Message = $"Risk Skoru: {verdict.RiskScore}/100 ({verdict.Verdict}) - TTD: {verdict.TimeToDetectMs:F1}ms",
                    Severity = verdict.Verdict == RealTimeVerdict.Unknown ? "Warning" :
                        verdict.RiskScore >= 85 ? "Danger" : (verdict.RiskScore >= 60 ? "Warning" : "Success"),
                    Timestamp = DateTime.Now
                });

                // Stage 5: Policy Enforcement
                if (verdict.RecommendedPolicy == RealTimePolicyAction.BlockAndQuarantine)
                {
                    bool quarantined = false;
                    if (_policyEnforcer is IRealTimePolicyOutcomeEnforcer outcomes)
                        quarantined = await outcomes.EnforceQuarantineWithOutcomeAsync(evt, verdict, ct);
                    else
                        await _policyEnforcer.EnforceQuarantineAsync(evt, verdict, ct);
                    verdict.ActionTime = DateTime.UtcNow;

                    OnActivityLogged?.Invoke(new RealTimeActivityEvent
                    {
                        CorrelationId = evt.CorrelationId,
                        FileName = fileName,
                        FilePath = evt.NormalizedPath,
                        Stage = "ACTION_APPLIED",
                        Action = quarantined ? "QUARANTINED" : "QUARANTINE_UNCONFIRMED",
                        RiskScore = verdict.RiskScore,
                        Verdict = verdict.Verdict.ToString(),
                        TimeToActionMs = verdict.TimeToActionMs,
                        Message = quarantined
                            ? $"Müdahale: Karantina doğrulandı (TTA: {verdict.TimeToActionMs:F1}ms)"
                            : "Tehdit tespit edildi; karantina tamamlanmadı veya doğrulanamadı",
                        Severity = "Danger",
                        Timestamp = DateTime.Now
                    });
                }
                else if (verdict.RecommendedPolicy == RealTimePolicyAction.Warn)
                {
                    await _policyEnforcer.EnforceWarningAsync(evt, verdict, ct);
                    verdict.ActionTime = DateTime.UtcNow;

                    OnActivityLogged?.Invoke(new RealTimeActivityEvent
                    {
                        CorrelationId = evt.CorrelationId,
                        FileName = fileName,
                        FilePath = evt.NormalizedPath,
                        Stage = "ACTION_APPLIED",
                        Action = "WARN",
                        RiskScore = verdict.RiskScore,
                        Verdict = verdict.Verdict.ToString(),
                        TimeToActionMs = verdict.TimeToActionMs,
                        Message = $"Müdahale: Kullanıcı Uyarıldı, Dosya Korundu (TTA: {verdict.TimeToActionMs:F1}ms)",
                        Severity = "Warning",
                        Timestamp = DateTime.Now
                    });
                }
                else
                {
                    // Policy is Allow / Unknown - LOG ONLY, NEVER DELETE UNKNOWN!
                    verdict.ActionTime = DateTime.UtcNow;
                    bool inspected = verdict.Verdict == RealTimeVerdict.Clean && verdict.RecommendedPolicy == RealTimePolicyAction.Allow;
                    _logger?.LogInformation("File arrival {Path}: verdict {Verdict}; inspection completed: {Complete}", evt.NormalizedPath, verdict.Verdict, inspected);

                    OnActivityLogged?.Invoke(new RealTimeActivityEvent
                    {
                        CorrelationId = evt.CorrelationId,
                        FileName = fileName,
                        FilePath = evt.NormalizedPath,
                        Stage = "ACTION_APPLIED",
                        Action = inspected ? "ALLOWED" : "OBSERVED_UNVERIFIED",
                        RiskScore = verdict.RiskScore,
                        Verdict = verdict.Verdict.ToString(),
                        TimeToActionMs = verdict.TimeToActionMs,
                        Message = inspected ? "İnceleme tamamlandı; tehdit bulunmadı" : "İnceleme tamamlanamadı; dosya temiz ilan edilmedi",
                        Severity = inspected ? "Success" : "Warning",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error processing normalized real-time event for {Path}", evt.NormalizedPath);
                throw;
            }
        }

        public void Dispose()
        {
            Stop();
            _eventIngestor.Dispose();
        }
    }
}
