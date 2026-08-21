using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class SelectableThreatModel : ObservableObject
    {
        [ObservableProperty]
        private bool isSelected = true;

        [ObservableProperty]
        private string name = string.Empty;

        [ObservableProperty]
        private string threatType = "Kötücül Yazılım";

        [ObservableProperty]
        private string objectType = "Dosya";

        [ObservableProperty]
        private string location = string.Empty;

        public SecurityFinding Finding { get; set; } = new();
    }

    public partial class ScanViewModel : ObservableObject
    {
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly ISecurityFindingService? _findingService;
        private readonly IQuarantineService? _quarantineService;
        private readonly IAllowlistService? _allowlistService;
        private readonly IWindowsToastNotificationService? _toastService;

        private DispatcherTimer? _timer;
        private Stopwatch _stopwatch = new();

        [ObservableProperty]
        private string pageTitle = "Güvenlik Taraması";

        [ObservableProperty]
        private bool isScanning;

        [ObservableProperty]
        private bool isNotScanning = true;

        [ObservableProperty]
        private bool isScanFinishedView;

        [ObservableProperty]
        private bool isPaused;

        public string PauseButtonText => IsPaused ? "Devam Et" : "Duraklat";

        [ObservableProperty]
        private int progressPercentage;

        [ObservableProperty]
        private string currentFile = string.Empty;

        [ObservableProperty]
        private int scannedCount;

        [ObservableProperty]
        private string scannedItemsFormatted = "0";

        [ObservableProperty]
        private string scanDurationFormatted = "0d 00s";

        [ObservableProperty]
        private int totalCount;

        [ObservableProperty]
        private int findingsCount;

        [ObservableProperty]
        private int detectionsCount;

        [ObservableProperty]
        private bool hasFindings;

        [ObservableProperty]
        private bool hasNoFindings = true;

        [ObservableProperty]
        private string scanStatusText = "Taramaya hazır.";

        // ESET-Style 5-Step Checklist Indicators
        [ObservableProperty]
        private bool isStep1Done;

        [ObservableProperty]
        private bool isStep2Done;

        [ObservableProperty]
        private bool isStep3Done;

        [ObservableProperty]
        private bool isStep4Done;

        [ObservableProperty]
        private bool isStep5Active = true;

        [ObservableProperty]
        private ObservableCollection<SecurityFinding> scanFindings = new();

        [ObservableProperty]
        private ObservableCollection<SelectableThreatModel> threatResults = new();

        [ObservableProperty]
        private bool isAllSelected = true;

        [ObservableProperty]
        private SecurityFinding? selectedFinding;

        [ObservableProperty]
        private bool hasSelectedFinding;

        [ObservableProperty]
        private string selectedThreatCategory = "Şüpheli Dosya / Potansiyel Zararlı";

        [ObservableProperty]
        private string selectedInfectionVector = "İnternet tarayıcısı veya arşiv dosyası üzerinden indirilmiş olabilir.";

        [ObservableProperty]
        private string selectedRemediationAdvice = "1. Dosyayı hemen Karantina Kasasına kilitleyin.\n2. Arka plan kalkanı sistemi izlemeye devam edecektir.";

        [ObservableProperty]
        private bool hasTextPreview;

        [ObservableProperty]
        private string textPreviewContent = string.Empty;

        [ObservableProperty]
        private string textPreviewLineCount = string.Empty;

        [ObservableProperty]
        private bool isTextFile;

        public ScanViewModel(
            IScanCoordinatorService? scanCoordinator = null, 
            ISecurityFindingService? findingService = null,
            IQuarantineService? quarantineService = null,
            IAllowlistService? allowlistService = null,
            IWindowsToastNotificationService? toastService = null)
        {
            _scanCoordinator = scanCoordinator;
            _findingService = findingService;
            _quarantineService = quarantineService;
            _allowlistService = allowlistService;
            _toastService = toastService;

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += (s, e) =>
            {
                if (IsScanning)
                {
                    var elapsed = _stopwatch.Elapsed;
                    ScanDurationFormatted = $"{elapsed.Minutes}d {elapsed.Seconds:D2}s";
                }
            };

            if (_scanCoordinator != null)
            {
                _scanCoordinator.ProgressChanged += OnScanProgressChanged;
                _scanCoordinator.ScanCompleted += OnScanCompleted;

                SyncWithScanCoordinator();
            }
        }

        partial void OnSelectedFindingChanged(SecurityFinding? value)
        {
            HasSelectedFinding = value != null;
            if (value != null)
            {
                ComputeThreatIntelligence(value);
                LoadTextPreview(value.ObjectPath);
            }
            else
            {
                HasTextPreview = false;
                TextPreviewContent = string.Empty;
                TextPreviewLineCount = string.Empty;
                IsTextFile = false;
            }
        }

        private void LoadTextPreview(string? filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                HasTextPreview = false;
                TextPreviewContent = string.Empty;
                TextPreviewLineCount = string.Empty;
                IsTextFile = false;
                return;
            }

            try
            {
                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                var textExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ".txt", ".log", ".ini", ".cfg", ".xml", ".json", ".csv", ".md", ".inf",
                    ".htm", ".html", ".lua", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py",
                    ".c", ".cpp", ".h", ".cs", ".sql", ".sh", ".yml", ".yaml", ".conf", ".nfo"
                };

                IsTextFile = textExtensions.Contains(ext);

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs, Encoding.UTF8);

                var sb = new StringBuilder();
                int lineCount = 0;
                string? line;
                while ((line = reader.ReadLine()) != null && lineCount < 500)
                {
                    lineCount++;
                    sb.AppendLine($"{lineCount,4} | {line}");
                }

                if (lineCount > 0)
                {
                    TextPreviewContent = sb.ToString();
                    TextPreviewLineCount = $"{lineCount} satır metin incelendi" + (lineCount >= 500 ? " (İlk 500 satır sınırı)" : "");
                    HasTextPreview = true;
                }
                else
                {
                    TextPreviewContent = "(Dosya boş / Metin içeriği bulunamadı)";
                    TextPreviewLineCount = "0 satır";
                    HasTextPreview = true;
                }
            }
            catch (Exception ex)
            {
                TextPreviewContent = $"[Önizleme okunamadı: {ex.Message}]";
                TextPreviewLineCount = "Hata";
                HasTextPreview = true;
            }
        }

        private void ComputeThreatIntelligence(SecurityFinding f)
        {
            var title = (f.Title ?? "").ToLowerInvariant();
            var desc = (f.Description ?? "").ToLowerInvariant();

            if (title.Contains("keylog") || desc.Contains("keylog") || desc.Contains("klavye"))
            {
                SelectedThreatCategory = "⌨️ Keylogger (Klavye ve Şifre Dinleyici)";
                SelectedInfectionVector = "Korsan yazılımlar, sahte crack programları veya kimlik avı e-posta ekleri.";
                SelectedRemediationAdvice = "1. Dosyayı derhal Karantina Kasasına kilitleyin.\n2. Bankacılık ve e-posta parolalarınızı sıfırlayın.";
            }
            else if (title.Contains("ransom") || desc.Contains("ransom") || title.Contains("fidye"))
            {
                SelectedThreatCategory = "🔒 Fidye Yazılımı (Ransomware / Dosya Kilitleyici)";
                SelectedInfectionVector = "Güvensiz web sitelerinden indirilen dosyalar veya zararlı ofis makroları.";
                SelectedRemediationAdvice = "1. Dosyayı derhal Karantina Kasasına kilitleyin.\n2. Fidye Kalkanı'nın devrede olduğundan emin olun.";
            }
            else if (title.Contains("trojan") || desc.Contains("trojan") || desc.Contains("truva"))
            {
                SelectedThreatCategory = "🐎 Truva Atı (Trojan.Downloader / Arka Kapı)";
                SelectedInfectionVector = "Meşru bir program gibi kamufle edilmiş kurulum dosyaları.";
                SelectedRemediationAdvice = "1. Dosyayı Karantina Kasasına kilitleyin.\n2. Tam sistem taraması gerçekleştirin.";
            }
            else
            {
                SelectedThreatCategory = "⚠️ Şüpheli Kod / İstenmeyen Yazılım (PUP / RiskWare)";
                SelectedInfectionVector = "İnternetten indirilen üçüncü parti kurulum paketleri veya geçici dosyalar.";
                SelectedRemediationAdvice = "1. Dosyayı Karantina Kasasına kilitleyin.";
            }
        }

        public void SyncWithScanCoordinator()
        {
            if (_scanCoordinator == null) return;

            Application.Current?.Dispatcher?.Invoke(() =>
            {
                IsScanning = _scanCoordinator.IsScanning;
                IsNotScanning = !_scanCoordinator.IsScanning;
                ProgressPercentage = (int)_scanCoordinator.ProgressPercent;
                CurrentFile = _scanCoordinator.CurrentFile;
                ScannedCount = _scanCoordinator.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                TotalCount = _scanCoordinator.TotalFiles;
                FindingsCount = _scanCoordinator.FindingsCount;
                DetectionsCount = FindingsCount;
                ScanStatusText = _scanCoordinator.StatusText;

                UpdateChecklistSteps(ProgressPercentage);
            });
        }

        [RelayCommand]
        public void OpenActiveScanWindow()
        {
            Views.ActiveScanWindow.ShowScanWindow(this);
        }

        private void OnScanProgressChanged(ScanProgress p)
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                IsScanning = true;
                IsNotScanning = false;
                IsScanFinishedView = false;
                ProgressPercentage = (int)p.ProgressPercent;
                CurrentFile = p.CurrentFile;
                ScannedCount = p.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                TotalCount = p.TotalFiles;
                FindingsCount = p.FindingsCount;
                DetectionsCount = FindingsCount;
                if (!IsPaused)
                {
                    ScanStatusText = $"{p.ScanType} taraması işleniyor...";
                }

                UpdateChecklistSteps(ProgressPercentage);
            });
        }

        private void UpdateChecklistSteps(int pct)
        {
            IsStep1Done = pct >= 8;
            IsStep2Done = pct >= 20;
            IsStep3Done = pct >= 35;
            IsStep4Done = pct >= 50;
            IsStep5Active = pct < 100;
        }

        private void OnScanCompleted(ScanResult result)
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                IsScanning = false;
                IsNotScanning = true;
                IsPaused = false;
                _stopwatch.Stop();
                _timer?.Stop();
                OnPropertyChanged(nameof(PauseButtonText));

                var elapsed = _stopwatch.Elapsed;
                ScanDurationFormatted = $"{elapsed.Minutes}d {elapsed.Seconds:D2}s";

                ProgressPercentage = 100;
                ScannedCount = result.ScannedFiles;
                ScannedItemsFormatted = $"{ScannedCount:N0}";
                TotalCount = result.TotalFiles;
                FindingsCount = result.Findings.Count;
                DetectionsCount = FindingsCount;

                IsStep1Done = true;
                IsStep2Done = true;
                IsStep3Done = true;
                IsStep4Done = true;
                IsStep5Active = false;

                ScanFindings.Clear();
                ThreatResults.Clear();

                if (result.Findings != null)
                {
                    foreach (var f in result.Findings)
                    {
                        ScanFindings.Add(f);

                        string cat = f.RiskLevel == RiskLevel.ConfirmedMalicious ? "Kötücül Yazılım" :
                                     f.RiskLevel == RiskLevel.HighRisk ? "Truva Atı / Riskli Kod" : "RiskWare.Agent";

                        ThreatResults.Add(new SelectableThreatModel
                        {
                            IsSelected = true,
                            Name = !string.IsNullOrWhiteSpace(f.ObjectName) ? f.ObjectName : System.IO.Path.GetFileName(f.ObjectPath),
                            ThreatType = cat,
                            ObjectType = f.ObjectPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? "Bellek / Yürütülebilir" : "Dosya",
                            Location = f.ObjectPath,
                            Finding = f
                        });
                    }
                }

                HasFindings = ScanFindings.Count > 0;
                HasNoFindings = ScanFindings.Count == 0;
                IsScanFinishedView = true;

                if (HasNoFindings)
                {
                    ScanStatusText = $"Tarama tamamlandı. {result.ScannedFiles:N0} dosya incelendi, sistem tamamen temiz.";
                    _toastService?.ShowToast(
                        "Sistem Güvende",
                        $"Tehdit taraması tamamlandı: {result.ScannedFiles:N0} dosya incelendi, herhangi bir virüse rastlanmadı.",
                        "Success");
                }
                else
                {
                    ScanStatusText = $"Tehdit Taraması Sonuçları: {ScanFindings.Count} adet zararlı tespit edildi.";
                    _toastService?.ShowToast(
                        "Tehdit Kaldırıldı ve Karantinaya Alındı",
                        $"{ScanFindings.Count} adet zararlı yazılım tespit edildi ve karantinaya kilitlendi.",
                        "Danger");
                }
            });
        }

        [RelayCommand]
        public async Task StartQuickScanAsync()
        {
            await RunScanAsync(ScanType.Quick, string.Empty);
        }

        [RelayCommand]
        public async Task StartFullScanAsync()
        {
            await RunScanAsync(ScanType.Full, string.Empty);
        }

        [RelayCommand]
        public async Task StartCustomScanAsync()
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog();
            if (dialog.ShowDialog() == true)
            {
                await RunScanAsync(ScanType.Custom, dialog.FolderName);
            }
        }

        public async Task StartCustomPathScanAsync(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            await RunScanAsync(ScanType.Custom, path);
        }

        [RelayCommand]
        public void ToggleSelectAll()
        {
            IsAllSelected = !IsAllSelected;
            foreach (var item in ThreatResults)
            {
                item.IsSelected = IsAllSelected;
            }
        }

        [RelayCommand]
        public void CloseResults()
        {
            IsScanFinishedView = false;
            ScanFindings.Clear();
            ThreatResults.Clear();
            HasFindings = false;
            HasNoFindings = true;
            ScanStatusText = "Taramaya hazır.";
        }

        [RelayCommand]
        public void TogglePauseResume()
        {
            if (_scanCoordinator == null || !IsScanning) return;

            if (IsPaused)
            {
                _scanCoordinator.ResumeScan();
                IsPaused = false;
                _stopwatch.Start();
                _timer?.Start();
                ScanStatusText = "Tarama devam ediyor...";
            }
            else
            {
                _scanCoordinator.PauseScan();
                IsPaused = true;
                _stopwatch.Stop();
                _timer?.Stop();
                ScanStatusText = "Tarama duraklatıldı.";
            }
            OnPropertyChanged(nameof(PauseButtonText));
        }

        [RelayCommand]
        public void CancelScan()
        {
            if (_scanCoordinator != null)
            {
                _scanCoordinator.CancelScan();
                _stopwatch.Stop();
                _timer?.Stop();
                IsScanning = false;
                IsNotScanning = true;
                IsPaused = false;
                IsScanFinishedView = false;
                ScanStatusText = "Tarama iptal edildi.";
                OnPropertyChanged(nameof(PauseButtonText));
            }
        }

        [RelayCommand]
        public async Task QuarantineSelectedAsync()
        {
            if (_quarantineService == null || ThreatResults.Count == 0) return;

            var selectedItems = ThreatResults.Where(t => t.IsSelected).ToList();
            int count = 0;

            foreach (var item in selectedItems)
            {
                try
                {
                    if (File.Exists(item.Location))
                    {
                        bool ok = await _quarantineService.QuarantineFileAsync(item.Location, item.Finding.Title);
                        if (ok)
                        {
                            item.Finding.Status = FindingStatus.Resolved;
                            if (_findingService != null) await _findingService.UpdateFindingAsync(item.Finding);
                            ThreatResults.Remove(item);
                            ScanFindings.Remove(item.Finding);
                            count++;
                        }
                    }
                    else
                    {
                        ThreatResults.Remove(item);
                    }
                }
                catch { }
            }

            FindingsCount = ThreatResults.Count;
            DetectionsCount = FindingsCount;
            HasFindings = FindingsCount > 0;
            HasNoFindings = FindingsCount == 0;

            if (count > 0)
            {
                _toastService?.ShowToast(
                    "Tehdit Kaldırıldı",
                    $"{count} adet zararlı tehdit başarıyla Karantina Kasasına kilitlendi.",
                    "Success");
            }

            if (ThreatResults.Count == 0)
            {
                IsScanFinishedView = false;
            }
        }

        private async Task RunScanAsync(ScanType scanType, string customPath)
        {
            if (_scanCoordinator == null || IsScanning) return;

            IsScanning = true;
            IsNotScanning = false;
            IsScanFinishedView = false;
            IsPaused = false;
            ProgressPercentage = 0;
            ScannedCount = 0;
            ScannedItemsFormatted = "0";
            FindingsCount = 0;
            DetectionsCount = 0;
            ScanFindings.Clear();
            ThreatResults.Clear();
            HasFindings = false;
            HasNoFindings = true;
            ScanStatusText = $"{scanType} taraması işleniyor...";

            _stopwatch.Restart();
            _timer?.Start();

            // Open the dedicated animated scanning window per user directive
            Views.ActiveScanWindow.ShowScanWindow(this);

            await _scanCoordinator.StartScanAsync(scanType, customPath);
        }
    }
}