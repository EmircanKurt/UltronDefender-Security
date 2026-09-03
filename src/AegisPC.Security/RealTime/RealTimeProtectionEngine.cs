using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
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
        private bool _isRunning;
        private readonly object _lock = new();
        private Timer? _cacheCleanupTimer;

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
            ILogger<RealTimeProtectionEngine>? logger = null)
            : this(
                new RealTimeEventIngestor(),
                new RealTimeStabilityChecker(),
                new RealTimeVerdictProcessor(hashService, signatureVerifier, riskScoringEngine, logger),
                new RealTimePolicyEnforcer(quarantineService, findingService, auditLogService, logger),
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
                _engineCts = new CancellationTokenSource();

                // 1. Setup Watchers on Critical Directories
                if (watchDefaultLocations)
                {
                    SetupFileSystemWatchers();
                }

                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = true; } catch { }
                }

                // 2. Start Background Multi-Worker Pool Consumers
                int workerCount = Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
                _eventIngestor.StartWorkers(workerCount, HandleNormalizedEventAsync, _engineCts.Token);

                // 3. Start WMI Dynamic Removable Media / USB Listener
                StartUsbArrivalListener();

                _cacheCleanupTimer = new Timer(_ => _verdictProcessor.CleanupCache(), null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));

                _logger?.LogInformation("Ultron Defender Real-Time Protection Engine started successfully with {Workers} workers.", workerCount);
                OnProtectionHealthChanged?.Invoke(true, "Sağlıklı - Tüm dizinler ve USB izleniyor");
            }
        }

        public void Stop()
        {
            lock (_lock)
            {
                if (!_isRunning) return;
                _isRunning = false;

                StopUsbArrivalListener();

                foreach (var w in _watchers)
                {
                    try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
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
                    Severity = verdict.RiskScore >= 70 ? "Danger" : (verdict.RiskScore >= 50 ? "Warning" : "Success"),
                    Timestamp = DateTime.Now
                });

                // Stage 5: Policy Enforcement
                if (verdict.RecommendedPolicy == RealTimePolicyAction.BlockAndQuarantine)
                {
                    await _policyEnforcer.EnforceQuarantineAsync(evt, verdict, ct);
                    verdict.ActionTime = DateTime.UtcNow;

                    OnActivityLogged?.Invoke(new RealTimeActivityEvent
                    {
                        CorrelationId = evt.CorrelationId,
                        FileName = fileName,
                        FilePath = evt.NormalizedPath,
                        Stage = "ACTION_APPLIED",
                        Action = "QUARANTINED",
                        RiskScore = verdict.RiskScore,
                        Verdict = verdict.Verdict.ToString(),
                        TimeToActionMs = verdict.TimeToActionMs,
                        Message = $"Müdahale: Karantinaya Alındı (TTA: {verdict.TimeToActionMs:F1}ms)",
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
                    _logger?.LogInformation("Instant File Arrival: '{Path}' evaluated as {Verdict} (TimeToDetect: {Ttd:F1}ms). Allowed.", evt.NormalizedPath, verdict.Verdict, verdict.TimeToDetectMs);

                    OnActivityLogged?.Invoke(new RealTimeActivityEvent
                    {
                        CorrelationId = evt.CorrelationId,
                        FileName = fileName,
                        FilePath = evt.NormalizedPath,
                        Stage = "ACTION_APPLIED",
                        Action = "ALLOWED",
                        RiskScore = verdict.RiskScore,
                        Verdict = verdict.Verdict.ToString(),
                        TimeToActionMs = verdict.TimeToActionMs,
                        Message = $"Müdahale: İzin Verildi (TTA: {verdict.TimeToActionMs:F1}ms)",
                        Severity = "Success",
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
            }
        }

        public void Dispose()
        {
            Stop();
            _eventIngestor.Dispose();
        }
    }
}
