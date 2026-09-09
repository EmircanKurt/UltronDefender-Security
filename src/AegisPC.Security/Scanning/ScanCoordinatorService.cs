using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class ScanCoordinatorService : IScanCoordinatorService
    {
        private readonly IFileScanner _fileScanner;
        private readonly ISecurityFindingService _findingService;
        private readonly IQuarantineService? _quarantineService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<ScanCoordinatorService>? _logger;

        private CancellationTokenSource? _scanCts;
        private readonly object _lock = new();
        private readonly List<SecurityFinding> _currentFindings = new();
        private ScanSession? _currentSession;
        private Task<ScanResult?>? _activeScanTask;

        private bool _isExternalScanRunning = false;
        public bool IsExternalScanRunning => _isExternalScanRunning;
        public bool IsScanning { get; private set; }
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
            ILogger<ScanCoordinatorService>? logger = null)
        {
            _fileScanner = fileScanner;
            _findingService = findingService;
            _quarantineService = quarantineService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public void RegisterExternalScanProgress(ScanProgress progress)
        {
            lock (_lock)
            {
                _isExternalScanRunning = true;
                IsScanning = true;
                CurrentScanType = progress.ScanType;
                ProgressPercent = progress.ProgressPercent;
                CurrentFile = progress.CurrentFile;
                ScannedFiles = progress.ScannedFiles;
                TotalFiles = progress.TotalFiles;
                ElapsedTime = progress.ElapsedTime;
                StatusText = $"Arka plan başlangıç taraması: {progress.ScannedFiles:N0} dosya incelendi (%{(int)progress.ProgressPercent})";
            }
            try
            {
                ProgressChanged?.Invoke(progress);
            }
            catch { }
        }

        public void CompleteExternalScan(ScanResult result)
        {
            lock (_lock)
            {
                _isExternalScanRunning = false;
                IsScanning = false;
                ProgressPercent = 100;
                ScannedFiles = result.ScannedFiles;
                TotalFiles = result.TotalFiles;
                ElapsedTime = result.ElapsedMs > 0 ? TimeSpan.FromMilliseconds(result.ElapsedMs) : TimeSpan.Zero;
                StatusText = $"Başlangıç taraması tamamlandı. {result.ScannedFiles:N0} dosya incelendi.";
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
            catch { }
        }

        public Task<ScanResult?> StartScanAsync(ScanType scanType, string customPath = "")
        {
            IScanSession? sessionToNotify = null;
            Task<ScanResult?>? runningTask = null;

            lock (_lock)
            {
                // Zaten çalışan bir tarama varsa mükerrer başlatma; mevcut aktif oturumu ve görevi dön
                if (IsScanning && _activeScanTask != null && !_activeScanTask.IsCompleted)
                {
                    _logger?.LogInformation("Scan is already in progress ({Type}). Returning existing active session.", CurrentScanType);
                    sessionToNotify = _currentSession;
                    runningTask = _activeScanTask;
                }
            }

            if (runningTask != null && sessionToNotify != null)
            {
                try
                {
                    ScanSessionStarted?.Invoke(sessionToNotify);
                }
                catch { }
                return runningTask;
            }

            ScanSession session;
            lock (_lock)
            {
                _isExternalScanRunning = false;
                IsScanning = true;
                CurrentScanType = scanType;
                ProgressPercent = 0;
                CurrentFile = "Tarama başlatılıyor...";
                ScannedFiles = 0;
                TotalFiles = 0;
                _currentFindings.Clear();
                StatusText = $"{scanType} taraması çalışıyor...";
                ElapsedTime = TimeSpan.Zero;
                _scanCts = new CancellationTokenSource();

                session = new ScanSession(
                    scanType,
                    customPath,
                    _scanCts,
                    PauseScan,
                    ResumeScan,
                    CancelScan);
                _currentSession = session;
            }

            try
            {
                ScanSessionStarted?.Invoke(session);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error notifying ScanSessionStarted listeners");
            }

            var scanTask = RunScanInternalAsync(session, scanType, customPath, _scanCts.Token);
            lock (_lock)
            {
                _activeScanTask = scanTask;
            }

            return scanTask;
        }

        private async Task<ScanResult?> RunScanInternalAsync(
            ScanSession session,
            ScanType scanType,
            string customPath,
            CancellationToken cancellationToken)
        {
            var progressHandler = new Progress<ScanProgress>(p =>
            {
                ProgressPercent = p.ProgressPercent;
                CurrentFile = p.CurrentFile;
                ScannedFiles = p.ScannedFiles;
                TotalFiles = p.TotalFiles;
                ElapsedTime = p.ElapsedTime;
                StatusText = $"{CurrentScanType} taraması: {p.ScannedFiles:N0} dosya incelendi";
                session.LatestProgress = p;

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

                // GÖREV 7: Risk skoru 85 ve üzeri olan zararlılar otomatik karantinaya alınır.
                // 60-84 arası şüpheli bulgular için kullanıcı uyarısı/olay kaydı oluşturulur.
                if (result?.Findings != null && result.Findings.Count > 0)
                {
                    result.Findings.RemoveAll(f => f.Status == FindingStatus.Resolved || f.IsAllowlisted);

                    foreach (var finding in result.Findings)
                    {
                        if (cancellationToken.IsCancellationRequested) break;

                        if (finding.RiskScore >= 85)
                        {
                            if (_quarantineService != null && !string.IsNullOrWhiteSpace(finding.ObjectPath))
                            {
                                try
                                {
                                    var qSuccess = await _quarantineService.QuarantineFileAsync(
                                        finding.ObjectPath,
                                        $"Otomatik Karantina (Risk Puanı: {finding.RiskScore}): {finding.Title}",
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
                                            catch { }
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger?.LogError(ex, "Otomatik karantinaya alma hatası: {Path}", finding.ObjectPath);
                                }
                            }
                        }
                        else if (finding.RiskScore >= 60 && finding.RiskScore < 85)
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
                                catch { }
                            }
                        }
                    }
                }

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
                }
            }
            catch (OperationCanceledException)
            {
                lock (_lock)
                {
                    StatusText = "Tarama kullanıcı tarafından durduruldu.";
                    CurrentFile = "Durduruldu.";

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
                    StatusText = $"Tarama hatası: {ex.Message}";
                    CurrentFile = "Hata oluştu.";
                }
            }
            finally
            {
                session.MarkEnded();

                lock (_lock)
                {
                    IsScanning = false;
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

        public bool IsPaused => _fileScanner.IsPaused;

        public void PauseScan()
        {
            lock (_lock)
            {
                if (!IsScanning) return;
                _fileScanner.PauseScan();
                StatusText = "Tarama duraklatıldı.";
            }
        }

        public void ResumeScan()
        {
            lock (_lock)
            {
                if (!IsScanning) return;
                _fileScanner.ResumeScan();
                StatusText = $"{CurrentScanType} taraması çalışıyor...";
            }
        }

        public void CancelScan()
        {
            lock (_lock)
            {
                if (!IsScanning || _scanCts == null) return;
                try
                {
                    if (IsPaused)
                    {
                        _fileScanner.ResumeScan(); // Ensure workers unblock to process cancellation
                    }
                    _scanCts.Cancel();
                    StatusText = "Tarama iptal ediliyor...";
                }
                catch { }
            }
        }
    }
}
