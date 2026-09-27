using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class ScanCoordinatorService : IScanCoordinatorService, IBackgroundScanCoordinator
    {
        private readonly IFileScanner _fileScanner;
        private readonly ISecurityFindingService _findingService;
        private readonly IQuarantineService? _quarantineService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ISettingsService? _settingsService;
        private readonly IPolicyEngine? _policyEngine;
        private readonly ILogger<ScanCoordinatorService>? _logger;

        private CancellationTokenSource? _scanCts;
        private readonly object _lock = new();
        private readonly List<SecurityFinding> _currentFindings = new();
        private ScanSession? _currentSession;
        private Task<ScanResult?>? _activeScanTask;

        private Action? _externalPauseAction;
        private Action? _externalResumeAction;
        private Action? _externalCancelAction;

        private sealed class ExternalScannerSubscription : IDisposable
        {
            private readonly Action _onDispose;
            private int _disposed;

            public ExternalScannerSubscription(Action onDispose)
            {
                _onDispose = onDispose;
            }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _disposed, 1) == 0)
                {
                    _onDispose();
                }
            }
        }

        private bool _isExternalScanRunning = false;
        public bool IsExternalScanRunning => _isExternalScanRunning;
        private volatile ScanState _state = ScanState.Idle;
        public ScanState State => _state;
        private volatile ScanStopReason _stopReason = ScanStopReason.None;
        public ScanStopReason StopReason => _stopReason;
        public bool IsScanning => _state == ScanState.Scanning || _state == ScanState.Paused || _state == ScanState.Cancelling;
        public ScanType CurrentScanType { get; private set; } = ScanType.Quick;
        public double ProgressPercent { get; private set; }
        public string CurrentFile { get; private set; } = string.Empty;
        public int ScannedFiles { get; private set; }
        public int TotalFiles { get; private set; }
        public int FindingsCount => _currentFindings.Count;
        public string StatusText { get; private set; } = "Taramaya hazır.";
        public TimeSpan ElapsedTime { get; private set; } = TimeSpan.Zero;
        public IScanSession? CurrentSession
        {
            get
            {
                lock (_lock) return _currentSession;
            }
        }

        public IReadOnlyList<SecurityFinding> CurrentFindings
        {
            get
            {
                lock (_lock)
                {
                    return _currentFindings.ToList();
                }
            }
        }

        public event Action<IScanSession>? ScanSessionStarted;
        public event Action<ScanProgress>? ProgressChanged;
        public event Action<ScanResult>? ScanCompleted;

        public ScanCoordinatorService(
            IFileScanner fileScanner,
            ISecurityFindingService findingService,
            IQuarantineService? quarantineService = null,
            IAuditLogService? auditLogService = null,
            ISettingsService? settingsService = null,
            IPolicyEngine? policyEngine = null,
            ILogger<ScanCoordinatorService>? logger = null)
        {
            _fileScanner = fileScanner;
            _findingService = findingService;
            _quarantineService = quarantineService;
            _auditLogService = auditLogService;
            _settingsService = settingsService;
            _policyEngine = policyEngine;
            _logger = logger;
        }

        public IDisposable RegisterExternalScanner(Action pauseAction, Action resumeAction, Action cancelAction)
        {
            lock (_lock)
            {
                _isExternalScanRunning = true;
                _externalPauseAction = pauseAction;
                _externalResumeAction = resumeAction;
                _externalCancelAction = cancelAction;
            }

            return new ExternalScannerSubscription(() =>
            {
                lock (_lock)
                {
                    _isExternalScanRunning = false;
                    _externalPauseAction = null;
                    _externalResumeAction = null;
                    _externalCancelAction = null;
                }
            });
        }

        public void RegisterExternalScanProgress(ScanProgress progress)
        {
            lock (_lock)
            {
                _isExternalScanRunning = true;
                if (_state != ScanState.Paused && _state != ScanState.Cancelling && _state != ScanState.Cancelled)
                {
                    _state = ScanState.Scanning;
                    _stopReason = ScanStopReason.None;
                }
                CurrentScanType = progress.ScanType;
                ProgressPercent = progress.ProgressPercent;
                CurrentFile = progress.CurrentFile;
                ScannedFiles = progress.ScannedFiles;
                TotalFiles = progress.TotalFiles;
                ElapsedTime = progress.ElapsedTime;
                if (_state != ScanState.Paused && _state != ScanState.Cancelling && _state != ScanState.Cancelled)
                {
                    StatusText = $"Arka plan başlangıç taraması: {progress.ScannedFiles:N0} dosya incelendi (%{(int)progress.ProgressPercent})";
                }
            }
            try
            {
                ProgressChanged?.Invoke(progress);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Subscriber threw exception on ProgressChanged event.");
            }
        }

        public void CompleteExternalScan(ScanResult result)
        {
            lock (_lock)
            {
                _isExternalScanRunning = false;
                if (result.Status == ScanStatus.Cancelled)
                {
                    _state = ScanState.Cancelled;
                    _stopReason = ScanStopReason.UserCancelled;
                    StatusText = "Tarama kullanıcı tarafından durduruldu.";
                    CurrentFile = "İptal edildi.";
                }
                else
                {
                    _state = ScanState.Completed;
                    _stopReason = ScanStopReason.CompletedNormally;
                    ProgressPercent = 100;
                    StatusText = $"Başlangıç taraması tamamlandı. {result.ScannedFiles:N0} dosya incelendi.";
                }

                ScannedFiles = result.ScannedFiles;
                TotalFiles = result.TotalFiles;
                ElapsedTime = result.ElapsedMs > 0 ? TimeSpan.FromMilliseconds(result.ElapsedMs) : TimeSpan.Zero;
                _currentFindings.Clear();
                if (result.Findings != null)
                {
                    _currentFindings.AddRange(result.Findings);
                }
            }
            try
            {
                ScanCompleted?.Invoke(result);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Subscriber threw exception on ScanCompleted event.");
            }
        }

        public Task<ScanResult?> StartScanAsync(ScanType scanType, string customPath = "")
            => StartOwnedScan(scanType, customPath, CancellationToken.None, background: false);

        /// <summary>Atomically claims an idle coordinator and binds cancellation to that scan only.</summary>
        public Task<ScanResult?> TryStartBackgroundScanAsync(ScanType scanType, CancellationToken cancellationToken)
            => StartOwnedScan(scanType, string.Empty, cancellationToken, background: true);

        /// <summary>Applies an owned profile only when no manual or external scan is active.</summary>
        public Task<ScanResult?> TryStartBackgroundScanAsync(ScanType scanType, CancellationToken cancellationToken, Action beforeOwnedScanStarts)
            => StartOwnedScan(scanType, string.Empty, cancellationToken, background: true, beforeOwnedScanStarts);

        private Task<ScanResult?> StartOwnedScan(ScanType scanType, string customPath,
            CancellationToken cancellationToken, bool background, Action? beforeOwnedScanStarts = null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ScanSession session;
            TaskCompletionSource<ScanResult?> completion;
            lock (_lock)
            {
                if (_activeScanTask != null && !_activeScanTask.IsCompleted)
                {
                    return background ? Task.FromResult<ScanResult?>(null) : _activeScanTask;
                }
                if (_isExternalScanRunning) return Task.FromResult<ScanResult?>(null);
                _isExternalScanRunning = false;
                _state = ScanState.Scanning;
                _stopReason = ScanStopReason.None;
                CurrentScanType = scanType;
                ProgressPercent = 0;
                CurrentFile = "Tarama başlatılıyor...";
                ScannedFiles = 0;
                TotalFiles = 0;
                _currentFindings.Clear();
                StatusText = $"{scanType} taraması çalışıyor...";
                ElapsedTime = TimeSpan.Zero;
                _scanCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                session = new ScanSession(
                    scanType,
                    customPath,
                    _scanCts,
                    () => { }, () => { }, () => { });
                _currentSession = session;
                // Replace the temporary callbacks with identity-bound actions (never a mutable CTS).
                session.SetOwnerActions(() => ApplyToOwnedSession(session.SessionId, PauseScan),
                    () => ApplyToOwnedSession(session.SessionId, ResumeScan),
                    () => ApplyToOwnedSession(session.SessionId, CancelScan));
                completion = new TaskCompletionSource<ScanResult?>(TaskCreationOptions.RunContinuationsAsynchronously);
                _activeScanTask = completion.Task;
            }

            try { beforeOwnedScanStarts?.Invoke(); }
            catch (Exception ex)
            {
                lock (_lock)
                {
                    session.MarkEnded();
                    _currentSession = null;
                    _scanCts?.Dispose();
                    _scanCts = null;
                    _activeScanTask = null;
                    _state = ScanState.Failed;
                    _stopReason = ScanStopReason.Error;
                    StatusText = "Tarama kaynak profili uygulanamadı.";
                }
                completion.TrySetException(ex);
                return completion.Task;
            }

            try
            {
                ScanSessionStarted?.Invoke(session);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error notifying ScanSessionStarted listeners");
            }

            _ = CompleteOwnedScanAsync(session, scanType, customPath, completion);
            return completion.Task;
        }

        private void ApplyToOwnedSession(Guid? sessionId, Action action)
        {
            lock (_lock)
            {
                if (sessionId != null && _currentSession?.SessionId == sessionId) action();
            }
        }

        private async Task CompleteOwnedScanAsync(ScanSession session, ScanType scanType, string path,
            TaskCompletionSource<ScanResult?> completion)
        {
            try { completion.TrySetResult(await RunScanInternalAsync(session, scanType, path, session.CancellationToken)); }
            catch (Exception ex) { completion.TrySetException(ex); }
        }

        private async Task<ScanResult?> RunScanInternalAsync(
            ScanSession session,
            ScanType scanType,
            string customPath,
            CancellationToken cancellationToken)
        {
            var progressHandler = new Progress<ScanProgress>(p =>
            {
                lock (_lock)
                {
                if (_currentSession != session || !session.IsActive) return;
                ProgressPercent = p.ProgressPercent;
                CurrentFile = p.CurrentFile;
                ScannedFiles = p.ScannedFiles;
                TotalFiles = p.TotalFiles;
                ElapsedTime = p.ElapsedTime;
                if (_state == ScanState.Scanning)
                    StatusText = $"{CurrentScanType} taraması: {p.ScannedFiles:N0} dosya incelendi";
                session.LatestProgress = p;
                }

                try
                {
                    ProgressChanged?.Invoke(p);
                }
                catch (Exception ex)
                {
                    _logger?.LogTrace(ex, "Error notifying scan progress listeners");
                }
            });

            ScanResult? result = null;

            try
            {
                _logger?.LogInformation("Starting {ScanType} scan (path: '{Path}')", scanType, customPath);
                result = await _fileScanner.ScanDirectoryAsync(customPath, scanType, progressHandler, cancellationToken);

                if (cancellationToken.IsCancellationRequested || result?.Status == ScanStatus.Cancelled)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                if (result?.Findings != null && result.Findings.Count > 0)
                {
                    result.Findings.RemoveAll(f => f.Status == FindingStatus.Resolved || f.IsAllowlisted);

                    if (_policyEngine != null)
                    {
                        foreach (var finding in result.Findings)
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            try
                            {
                                await _policyEngine.EnforcePolicyAsync(finding, cancellationToken);
                            }
                            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                            catch (Exception ex)
                            {
                                _logger?.LogError(ex, "Politika infaz hatası: {Path}", finding.ObjectPath);
                            }
                        }
                    }
                    else
                    {
                        var enableAutoQuarantine = _settingsService?.GetSetting("EnableAutoQuarantine", true) ?? true;
                        var autoQuarantineThreshold = _settingsService?.GetSetting("AutoQuarantineThreshold", 85) ?? 85;
                        autoQuarantineThreshold = Math.Clamp(autoQuarantineThreshold, 0, 100);

                        foreach (var finding in result.Findings)
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            if (finding.IsAllowlisted || finding.Status != FindingStatus.Active) continue;

                            bool isConfirmedThreat = finding.Category is FindingCategory.KnownMalwareHash or FindingCategory.ConfirmedMalicious;
                            if (enableAutoQuarantine && isConfirmedThreat && finding.RiskScore >= autoQuarantineThreshold)
                            {
                                if (_quarantineService != null && !string.IsNullOrWhiteSpace(finding.ObjectPath))
                                {
                                    try
                                    {
                                        var qSuccess = _quarantineService is IContentBoundQuarantineService bound && await bound.TryQuarantineFileAsync(
                                            finding.ObjectPath,
                                            $"Otomatik Karantina (Risk Puanı: {finding.RiskScore}): {finding.Title}",
                                            finding.SHA256 ?? string.Empty,
                                            cancellationToken);

                                        if (qSuccess)
                                        {
                                            finding.Status = FindingStatus.Resolved;
                                            await _findingService.UpdateFindingAsync(finding, cancellationToken);
                                            _logger?.LogInformation("Zararlı dosya otomatik karantinaya alındı: {Path}", finding.ObjectPath);

                                            if (_auditLogService != null)
                                            {
                                                try
                                                {
                                                    await _auditLogService.LogActionAsync(
                                                        AuditAction.FileQuarantined,
                                                        "File",
                                                        finding.Title,
                                                        finding.ObjectPath,
                                                        $"Otomatik karantinaya alındı. Risk Skoru: {finding.RiskScore}",
                                                        AuditResult.Success,
                                                        null,
                                                        cancellationToken);
                                                }
                                                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                                                catch (Exception auditEx)
                                                {
                                                    _logger?.LogWarning(auditEx, "AuditLog recording failed for auto-quarantine of {Path}", finding.ObjectPath);
                                                }
                                            }
                                        }
                                    }
                                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                                    catch (Exception ex)
                                    {
                                        _logger?.LogError(ex, "Otomatik karantinaya alma hatası: {Path}", finding.ObjectPath);
                                    }
                                }
                            }
                            else if (finding.RiskScore >= 60)
                            {
                                if (_auditLogService != null)
                                {
                                    try
                                    {
                                        await _auditLogService.LogActionAsync(
                                            AuditAction.ScanCompleted,
                                            "File",
                                            finding.Title,
                                            finding.ObjectPath,
                                            $"Şüpheli dosya tespit edildi (Risk: {finding.RiskScore}). Kullanıcı uyarıldı, dosya korundu.",
                                            AuditResult.Success,
                                            null,
                                            cancellationToken);
                                    }
                                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                                    catch (Exception auditEx)
                                    {
                                        _logger?.LogWarning(auditEx, "AuditLog recording failed for suspicious finding warning of {Path}", finding.ObjectPath);
                                    }
                                }
                            }
                        }
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();
                lock (_lock)
                {
                    _currentFindings.Clear();
                    if (result?.Findings != null)
                    {
                        _currentFindings.AddRange(result.Findings);
                    }
                    if (result != null && result.ElapsedMs > 0)
                    {
                        ElapsedTime = TimeSpan.FromMilliseconds(result.ElapsedMs);
                    }
                    StatusText = $"Tarama tamamlandı. {result?.ScannedFiles:N0} dosya incelendi, {_currentFindings.Count} riskli bulgu.";
                    ProgressPercent = 100;
                    CurrentFile = "Tarama tamamlandı.";
                    _state = ScanState.Completed;
                    _stopReason = ScanStopReason.CompletedNormally;
                }
            }
            catch (Exception ex) when (cancellationToken.IsCancellationRequested || ex is OperationCanceledException || ex is ChannelClosedException)
            {
                lock (_lock)
                {
                    _state = ScanState.Cancelled;
                    _stopReason = ScanStopReason.UserCancelled;
                    StatusText = "Tarama kullanıcı tarafından durduruldu.";
                    CurrentFile = "İptal edildi.";

                    if (result?.Findings != null)
                    {
                        _currentFindings.Clear();
                        _currentFindings.AddRange(result.Findings);
                    }

                    result = new ScanResult
                    {
                        ScanType = scanType,
                        CustomPath = customPath,
                        TotalFiles = TotalFiles,
                        ScannedFiles = ScannedFiles,
                        Findings = _currentFindings.ToList(),
                        ElapsedMs = (long)ElapsedTime.TotalMilliseconds,
                        StartedAt = session.StartedAtUtc,
                        CompletedAt = DateTime.UtcNow,
                        Status = ScanStatus.Cancelled
                    };
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Scan failed with error: {Message}", ex.Message);
                lock (_lock)
                {
                    _state = ScanState.Failed;
                    _stopReason = ScanStopReason.Error;
                    StatusText = $"Tarama hatası: {ex.Message}";
                    CurrentFile = "Hata oluştu.";
                }
            }
            finally
            {
                session.MarkEnded();

                lock (_lock)
                {
                    if (_fileScanner.IsPaused)
                    {
                        try { _fileScanner.ResumeScan(); }
                        catch (Exception ex) { _logger?.LogWarning(ex, "Failed to resume scanner during cleanup."); }
                    }
                    if (_state == ScanState.Scanning)
                    {
                        _state = ScanState.Completed;
                        _stopReason = ScanStopReason.CompletedNormally;
                    }
                    _currentSession = null;
                    _activeScanTask = null;
                    _scanCts?.Dispose();
                    _scanCts = null;
                }

                if (result != null)
                {
                    try
                    {
                        ScanCompleted?.Invoke(result);
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "Error invoking ScanCompleted callback");
                    }
                }
            }

            return result;
        }

        public bool IsPaused
        {
            get
            {
                lock (_lock)
                {
                    return _state == ScanState.Paused || (_state == ScanState.Scanning && _fileScanner.IsPaused);
                }
            }
        }

        public void PauseScan()
        {
            Action? extPause = null;
            lock (_lock)
            {
                if (_state != ScanState.Scanning)
                {
                    return;
                }

                _fileScanner.PauseScan();
                extPause = _externalPauseAction;
                _state = ScanState.Paused;
                StatusText = "Tarama duraklatıldı.";
            }

            try
            {
                extPause?.Invoke();
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Error invoking external pause action.");
            }
        }

        public void ResumeScan()
        {
            Action? extResume = null;
            lock (_lock)
            {
                if (_fileScanner.IsPaused)
                {
                    _fileScanner.ResumeScan();
                }

                extResume = _externalResumeAction;

                if (_state == ScanState.Paused)
                {
                    _state = ScanState.Scanning;
                    StatusText = $"{CurrentScanType} taraması çalışıyor...";
                }
            }

            try
            {
                extResume?.Invoke();
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Error invoking external resume action.");
            }
        }

        public void CancelScan()
        {
            Action? extCancel = null;
            lock (_lock)
            {
                if (_state != ScanState.Scanning && _state != ScanState.Paused)
                {
                    return;
                }

                _state = ScanState.Cancelling;
                _stopReason = ScanStopReason.UserCancelled;
                StatusText = "Tarama iptal ediliyor...";

                try
                {
                    if (_fileScanner.IsPaused)
                    {
                        _fileScanner.ResumeScan();
                    }

                    _scanCts?.Cancel();
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "Exception during scan cancellation cleanup.");
                }

                extCancel = _externalCancelAction;
            }

            try
            {
                extCancel?.Invoke();
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Error invoking external cancel action.");
            }
        }
    }
}
