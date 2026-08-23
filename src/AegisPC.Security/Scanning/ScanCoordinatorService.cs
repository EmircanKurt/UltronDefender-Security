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
        private readonly ILogger<ScanCoordinatorService>? _logger;

        private CancellationTokenSource? _scanCts;
        private readonly object _lock = new();
        private readonly List<SecurityFinding> _currentFindings = new();

        private bool _isExternalScanRunning = false;
        public bool IsScanning { get; private set; }
        public ScanType CurrentScanType { get; private set; } = ScanType.Quick;
        public double ProgressPercent { get; private set; }
        public string CurrentFile { get; private set; } = string.Empty;
        public int ScannedFiles { get; private set; }
        public int TotalFiles { get; private set; }
        public int FindingsCount => _currentFindings.Count;
        public string StatusText { get; private set; } = "Taramaya hazır.";
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

        public event Action<ScanProgress>? ProgressChanged;
        public event Action<ScanResult>? ScanCompleted;

        public ScanCoordinatorService(
            IFileScanner fileScanner,
            ISecurityFindingService findingService,
            ILogger<ScanCoordinatorService>? logger = null)
        {
            _fileScanner = fileScanner;
            _findingService = findingService;
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

        public async Task<ScanResult?> StartScanAsync(ScanType scanType, string customPath = "")
        {
            CancellationTokenSource? oldCts = null;
            lock (_lock)
            {
                if (_scanCts != null && !_scanCts.IsCancellationRequested)
                {
                    oldCts = _scanCts;
                }

                _isExternalScanRunning = false;
                IsScanning = true;
                CurrentScanType = scanType;
                ProgressPercent = 0;
                CurrentFile = "Tarama başlatılıyor...";
                ScannedFiles = 0;
                TotalFiles = 0;
                _currentFindings.Clear();
                StatusText = $"{scanType} taraması çalışıyor...";
                _scanCts = new CancellationTokenSource();
            }

            if (oldCts != null)
            {
                try
                {
                    oldCts.Cancel();
                    oldCts.Dispose();
                }
                catch { }
                await Task.Delay(100);
            }

            var progressHandler = new Progress<ScanProgress>(p =>
            {
                ProgressPercent = p.ProgressPercent;
                CurrentFile = p.CurrentFile;
                ScannedFiles = p.ScannedFiles;
                TotalFiles = p.TotalFiles;
                StatusText = $"{CurrentScanType} taraması: {p.ScannedFiles:N0} dosya incelendi";

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
                result = await _fileScanner.ScanDirectoryAsync(customPath, scanType, progressHandler, _scanCts.Token);

                lock (_lock)
                {
                    _currentFindings.Clear();
                    if (result?.Findings != null)
                    {
                        _currentFindings.AddRange(result.Findings);
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
                lock (_lock)
                {
                    IsScanning = false;
                }

                if (result != null)
                {
                    try
                    {
                        ScanCompleted?.Invoke(result);
                    }
                    catch { }
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
