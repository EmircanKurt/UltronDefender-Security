using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Threading;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AegisPC.App.ViewModels
{
    /// <summary>
    /// Presents observed scan progress, final results, and user actions; partial modules handle synchronization, reports, and controls.
    /// </summary>
    public partial class ScanViewModel : ObservableObject
    {
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly ISecurityFindingService? _findingService;
        private readonly IQuarantineService? _quarantineService;
        private readonly IAllowlistService? _allowlistService;
        private readonly IWindowsToastNotificationService? _toastService;
        private readonly IScanResourceManager? _resourceManager;
        private readonly ISettingsService? _settingsService;
        private readonly IExclusionService? _exclusionService;
        private readonly AegisPC.ServiceContracts.IServiceIpcClient? _ipcClient;

        private DispatcherTimer? _timer;
        private Stopwatch _stopwatch = new();
        private TimeSpan _engineElapsedTime = TimeSpan.Zero;
        private DateTime _lastEngineUpdateUtc = DateTime.UtcNow;

        #region UI Başlık ve Tarama Durum Özellikleri
        /// <summary>
        /// Tarama sayfasının UI başlık metni.
        /// </summary>
        [ObservableProperty]
        private string pageTitle = "Güvenlik Taraması";

        /// <summary>
        /// Bir taramanın aktif olarak çalışıp çalışmadığını belirtir.
        /// </summary>
        [ObservableProperty]
        private bool isScanning;

        /// <summary>
        /// Taramanın çalışmadığı durum (buton ve kontrol erişilebilirlik bağlayıcısı).
        /// </summary>
        [ObservableProperty]
        private bool isNotScanning = true;

        /// <summary>
        /// Tarama tamamlandıktan sonra sonuç ekranının görüntülenip görüntülenmeyeceğini belirtir.
        /// </summary>
        [ObservableProperty]
        private bool isScanFinishedView;

        /// <summary>
        /// Taramanın kullanıcı tarafından duraklatılıp duraklatılmadığını belirtir.
        /// </summary>
        [ObservableProperty]
        private bool isPaused;

        /// <summary>
        /// Duraklat / Devam Et butonunun anlık durumuna göre gösterilecek metin.
        /// </summary>
        public string PauseButtonText => IsPaused ? "Devam Et" : "Duraklat";

        private volatile bool _isCancellationRequested;
        public bool IsCancellationRequested => _isCancellationRequested;
        /// <summary>Shows final engine status, without representing a failed scan as completed.</summary>
        public string ScanResultTitle => _isCancellationRequested ? "Tarama İptal Edildi" : _lastScanStatus == ScanStatus.Failed ? "Tarama Başarısız" : "Tarama Sonuçları";
        /// <summary>Describes observed coverage rather than certifying the safety of the system.</summary>
        public string CleanStateTitle => _isCancellationRequested ? "Tarama İptal Edildi" : _lastScanStatus == ScanStatus.Failed ? "Tarama Başarısız" : "İncelenen öğelerde açık bulgu yok";
        /// <summary>Retains coverage limitations for cancelled, failed, and partially inspected scans.</summary>
        public string CleanStateSubtitle => _isCancellationRequested 
            ? $"Tarama durduruldu; incelenmeyen dosyalar hakkında karar verilmedi. {ScannedItemsFormatted} öğe incelendi."
            : _lastScanStatus == ScanStatus.Failed || FailedCount > 0 || TimedOutCount > 0 || SkippedCount > 0
                ? "Kapsam eksik; atlanan veya incelenemeyen dosyalar için temiz kararı verilmedi."
                : "Bu sonuç sistemin bütünüyle güvenli olduğunu garanti etmez. Kapatılmış bulgular raporda korunur.";

        /// <summary>
        /// Taramanın ne çalıştığı ne de sonuç ekranında olduğu boşta / hazır durumu (ActiveScanWindow için).
        /// </summary>
        public bool IsIdleView => !IsScanning && !IsScanFinishedView;

        /// <summary>
        /// Tarama durumuna göre "Tarayıcı Penceresini Aç" veya "Aktif Taramayı Görüntüle" metni.
        /// </summary>
        public string OpenScanWindowButtonText => IsScanning ? "Aktif Taramayı Görüntüle" : "Tarayıcı Penceresini Aç";

        partial void OnIsScanningChanged(bool value)
        {
            OnPropertyChanged(nameof(IsIdleView));
            OnPropertyChanged(nameof(OpenScanWindowButtonText));
            UpdateChecklistSteps(ProgressPercentage);
        }

        partial void OnIsScanFinishedViewChanged(bool value)
        {
            OnPropertyChanged(nameof(IsIdleView));
        }

        partial void OnIsPausedChanged(bool value)
        {
            OnPropertyChanged(nameof(PauseButtonText));
        }
        #endregion

        #region İlerleme ve Sayaç Metrikleri
        /// <summary>
        /// Taramanın anlık yüzdelik tamamlanma oranı (0-100).
        /// </summary>
        [ObservableProperty]
        private int progressPercentage;

        partial void OnProgressPercentageChanged(int value)
        {
            UpdateChecklistSteps(value);
        }

        /// <summary>
        /// O an incelenmekte olan dosyanın adı veya yolu.
        /// </summary>
        [ObservableProperty]
        private string currentFile = string.Empty;

        /// <summary>
        /// Şimdiye kadar incelenen toplam dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int scannedCount;

        /// <summary>
        /// UI gösterimi için binlik basamak formatında taranan dosya sayısı metni.
        /// </summary>
        [ObservableProperty]
        private string scannedItemsFormatted = "0";

        /// <summary>
        /// Önbellek isabetiyle taranan dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int scannedFromCache;

        /// <summary>
        /// Güvenilir imza veya beyaz liste kontrolü ile hızlı atlanan dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int skippedSignedClean;

        /// <summary>
        /// Derin analiz ve özet hesaplamasıyla yeni taranan dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int newlyScanned;

        /// <summary>
        /// Taranan dosyaların detaylı kırılım metni (örn. "82.331 önbellekten • 3.900 imzalı geçti • 9.170 yeni tarandı").
        /// </summary>
        [ObservableProperty]
        private string scannedBreakdownFormatted = string.Empty;

        /// <summary>
        /// Tarama başlangıcından bu yana geçen sürenin biçimlendirilmiş metni (ör. 1 dk 24 sn veya 1 sa 05 dk 12 sn).
        /// </summary>
        [ObservableProperty]
        private string scanDurationFormatted = "0 dk 00 sn";

        /// <summary>
        /// Kalan tahmini tarama süresi ve dosya oranı metni (ör. Kalan: ~4 dk 12 sn (12.340 / 210.547 dosya)).
        /// </summary>
        [ObservableProperty]
        private string remainingEtaFormatted = string.Empty;

        /// <summary>
        /// Taranması planlanan toplam tahmini dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int totalCount;

        /// <summary>
        /// Tarama sırasında tespit edilen şüpheli veya zararlı bulgu sayısı.
        /// </summary>
        [ObservableProperty]
        private int findingsCount;

        /// <summary>
        /// Tespit sayısı (bulgu sayısı ile eşleşir).
        /// </summary>
        [ObservableProperty]
        private int detectionsCount;

        /// <summary>
        /// Listede tehdit bulunup bulunmadığını belirtir.
        /// </summary>
        [ObservableProperty]
        private bool hasFindings;

        /// <summary>
        /// Hiçbir tehdit tespit edilmediğini belirtir (Temiz sistem göstergesi).
        /// </summary>
        [ObservableProperty]
        private bool hasNoFindings = true;

        /// <summary>
        /// Kullanıcıya gösterilen anlık tarama durum açıklaması.
        /// </summary>
        [ObservableProperty]
        private string scanStatusText = "Taramaya hazır.";

        /// <summary>
        /// Atlanan dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int skippedCount;

        /// <summary>
        /// Taraması başarısız olan (I/O, bozuk dosya vb.) dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int failedCount;

        /// <summary>
        /// Per-file timeout (10s) sınırını aşarak zaman aşımına uğrayan dosya sayısı.
        /// </summary>
        [ObservableProperty]
        private int timedOutCount;
        /// <summary>Counts authoritative malware separately from review items and coverage gaps.</summary>
        [ObservableProperty] private int confirmedMaliciousCount;
        /// <summary>Counts non-authoritative review items, never calls them viruses.</summary>
        [ObservableProperty] private int suspiciousReviewCount;
        /// <summary>Explains the current security counters independently of incomplete file inspection.</summary>
        public string FindingBreakdownText => $"{ConfirmedMaliciousCount:N0} doğrulanmış • {SuspiciousReviewCount:N0} inceleme gereken";
        partial void OnConfirmedMaliciousCountChanged(int value) => OnPropertyChanged(nameof(FindingBreakdownText));
        partial void OnSuspiciousReviewCountChanged(int value) => OnPropertyChanged(nameof(FindingBreakdownText));

        /// <summary>
        /// Anlık işlemci kullanım yüzdesi.
        /// </summary>
        [ObservableProperty]
        private double cpuUsagePercent;

        /// <summary>
        /// Anlık bellek kullanım miktarı (MB).
        /// </summary>
        [ObservableProperty]
        private double ramUsageMb;

        /// <summary>
        /// Aktif tarama kaynak profili adı.
        /// </summary>
        [ObservableProperty]
        private string activeResourceProfileText = "Auto";

        /// <summary>
        /// Kullanıcı tarafından seçilen tarama kaynak modu.
        /// </summary>
        [ObservableProperty]
        private ScanResourceMode selectedResourceMode = ScanResourceMode.Auto;

        /// <summary>
        /// Anlık CPU ve RAM kullanım metni (ör. CPU: %14 • RAM: 180 MB).
        /// </summary>
        public string CpuAndRamFormatted => $"{(IsCpuTelemetryAvailable ? $"CPU: %{CpuUsagePercent:F1}" : "CPU: ölçülüyor")} • {(RamUsageMb > 0 ? $"RAM: {RamUsageMb:F0} MB" : "RAM: ölçülüyor")}";
        /// <summary>Distinguishes a measured zero CPU load from telemetry that has not yet collected a valid sample.</summary>
        [ObservableProperty] private bool isCpuTelemetryAvailable;
        partial void OnIsCpuTelemetryAvailableChanged(bool value) => OnPropertyChanged(nameof(CpuAndRamFormatted));
        partial void OnCpuUsagePercentChanged(double value) => OnPropertyChanged(nameof(CpuAndRamFormatted));
        partial void OnRamUsageMbChanged(double value) => OnPropertyChanged(nameof(CpuAndRamFormatted));
        #endregion

        #region Donanım Kaynak Uyarlaması ve Donma Önleme
        /// <summary>
        /// Algılanan sistem donanım profili ve bellek kotası özeti (Örn: 16 GB RAM • 1024 MB Kota • 6/8 Çekirdek).
        /// </summary>
        [ObservableProperty]
        private string hardwareTuningText = "⚡ Donanım Algılanıyor...";

        /// <summary>
        /// Donanım optimizasyonu ve donma önleme mekanizması detay açıklaması.
        /// </summary>
        [ObservableProperty]
        private string hardwareProfileDetail = "Sistem donmasını önlemek için bellek tavanı ve arka plan iş parçacığı önceliği devrededir.";
        #endregion


        #region Tehdit Koleksiyonları ve Seçim Durumları
        /// <summary>
        /// Tarama sonucunda tespit edilen tüm güvenlik bulgularının ham listesi.
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<SecurityFinding> scanFindings = new();

        /// <summary>
        /// UI üzerinde seçim kutusu ile listelenen tehdit modelleri koleksiyonu.
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<SelectableThreatModel> threatResults = new();

        /// <summary>
        /// Tablodaki tüm tehditlerin aynı anda seçili olup olmadığını belirtir.
        /// </summary>
        [ObservableProperty]
        private bool isAllSelected = true;

        /// <summary>
        /// Kullanıcının detaylarını görmek üzere tıkladığı güvenlik bulgusu.
        /// </summary>
        [ObservableProperty]
        private SecurityFinding? selectedFinding;

        /// <summary>
        /// Detay panelinde gösterilecek bir bulgu seçili olup olmadığını belirtir.
        /// </summary>
        [ObservableProperty]
        private bool hasSelectedFinding;

        /// <summary>
        /// Seçili tehdidin sınıflandırılmış başlığı.
        /// </summary>
        [ObservableProperty]
        private string selectedThreatCategory = "Şüpheli Dosya / Potansiyel Zararlı";

        /// <summary>
        /// Seçili tehdidin olası sisteme bulaşma vektörü.
        /// </summary>
        [ObservableProperty]
        private string selectedInfectionVector = "İnternet tarayıcısı veya arşiv dosyası üzerinden indirilmiş olabilir.";

        /// <summary>
        /// Kullanıcıya önerilen güvenlik aksiyon tavsiyesi.
        /// </summary>
        [ObservableProperty]
        private string selectedRemediationAdvice = "1. Dosyayı hemen Karantina Kasasına kilitleyin.\n2. Arka plan kalkanı sistemi izlemeye devam edecektir.";
        #endregion

        #region Dosya Önizleme Durumu
        /// <summary>
        /// Seçili dosyanın metin önizleme panelinde gösterilip gösterilemeyeceğini belirtir.
        /// </summary>
        [ObservableProperty]
        private bool hasTextPreview;

        /// <summary>
        /// Güvenli şekilde okunan ilk 500 satırlık metin içeriği.
        /// </summary>
        [ObservableProperty]
        private string textPreviewContent = string.Empty;

        /// <summary>
        /// Okunan satır sayısı bilgisi metni.
        /// </summary>
        [ObservableProperty]
        private string textPreviewLineCount = string.Empty;

        /// <summary>
        /// Dosyanın incelenebilir bir metin formatında olup olmadığını belirtir.
        /// </summary>
        [ObservableProperty]
        private bool isTextFile;
        #endregion

        /// <summary>
        /// Initializes optional scan services and per-user report storage; missing mutation providers fail closed instead of simulating success.
        /// </summary>
        public ScanViewModel(
            IScanCoordinatorService? scanCoordinator = null, 
            ISecurityFindingService? findingService = null,
            IQuarantineService? quarantineService = null,
            IAllowlistService? allowlistService = null,
            IWindowsToastNotificationService? toastService = null,
            IScanResourceManager? resourceManager = null,
            ISettingsService? settingsService = null,
            IExclusionService? exclusionService = null,
            AegisPC.ServiceContracts.IServiceIpcClient? ipcClient = null,
            Services.ScanReportHistoryStore? reportHistoryStore = null)
        {
            _scanCoordinator = scanCoordinator;
            _findingService = findingService;
            _quarantineService = quarantineService;
            _allowlistService = allowlistService;
            _toastService = toastService;
            _resourceManager = resourceManager;
            _settingsService = settingsService;
            _exclusionService = exclusionService;
            _ipcClient = ipcClient;
            _reportHistoryStore = reportHistoryStore ?? new Services.ScanReportHistoryStore();
            _persistReportHistory = reportHistoryStore != null || System.Windows.Application.Current != null;

            if (_resourceManager != null)
            {
                _resourceManager.ProfileChanged += profile =>
                {
                    System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        HardwareTuningText = profile.SummaryText;
                        ActiveResourceProfileText = profile.SummaryText;
                    });
                };
                HardwareTuningText = _resourceManager.ActiveProfile.SummaryText;
                ActiveResourceProfileText = _resourceManager.ActiveProfile.SummaryText;
            }
            else
            {
                HardwareTuningText = AegisPC.Security.Scanning.ScanQueueCoordinator.ActiveResourceSummary;
                ActiveResourceProfileText = AegisPC.Security.Scanning.ScanQueueCoordinator.ActiveResourceSummary;
            }

            var profile = ScanHardwareProfile.Detect();
            HardwareProfileDetail = $"{profile.TotalRamGb:F0} GB RAM; başlangıç tarama bütçesi {profile.MaxMemoryBudgetMb} MB, en fazla {profile.Concurrency} işçi. Canlı yük kaynak profilini değiştirebilir; bütçe tüm süreç için katı bellek sınırı değildir.";

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += (s, e) =>
            {
                if (IsScanning && !IsPaused)
                {
                    var currentElapsed = _engineElapsedTime > TimeSpan.Zero
                        ? _engineElapsedTime + (DateTime.UtcNow - _lastEngineUpdateUtc)
                        : _stopwatch.Elapsed;
                    ScanDurationFormatted = FormatDuration(currentElapsed);
                }
            };

            if (_scanCoordinator != null)
            {
                _scanCoordinator.ScanSessionStarted += OnScanSessionStarted;
                _scanCoordinator.ProgressChanged += OnScanProgressChanged;
                _scanCoordinator.ScanCompleted += OnScanCompleted;

                SyncWithScanCoordinator();
            }
        }

        private void OnScanSessionStarted(IScanSession session)
        {
            System.Windows.Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                if (!IsScanning || ProgressPercentage == 0)
                {
                    ResetScanState(session.ScanType);
                }
                else
                {
                    SyncWithScanCoordinator();
                }

                if (!App.IsStartMinimized)
                {
                    Views.ActiveScanWindow.ShowScanWindow(this);
                }
            });
        }

        /// <summary>
        /// Clears previous result and coverage counters before a new owned scan starts; it does not itself launch a scan.
        /// </summary>
        public void ResetScanState(ScanType scanType = ScanType.Quick)
        {
            IsScanning = true;
            IsNotScanning = false;
            IsScanFinishedView = false;
            IsPaused = false;
            ProgressPercentage = 0;
            ScannedCount = 0;
            ScannedItemsFormatted = "0";
            ScannedFromCache = 0;
            SkippedSignedClean = 0;
            NewlyScanned = 0;
            ScannedBreakdownFormatted = string.Empty;
            TotalCount = 0;
            FindingsCount = 0;
            DetectionsCount = 0;
            ConfirmedMaliciousCount = 0;
            SuspiciousReviewCount = 0;
            SkippedCount = 0;
            FailedCount = 0;
            TimedOutCount = 0;
            CpuUsagePercent = 0;
            RamUsageMb = 0;
            IsCpuTelemetryAvailable = false;
            _lastScanStatus = ScanStatus.Running;
            _confirmedActions.Clear();
            ScanFindings.Clear();
            ThreatResults.Clear();
            HasFindings = false;
            HasNoFindings = true;
            _engineElapsedTime = TimeSpan.Zero;
            _lastEngineUpdateUtc = DateTime.UtcNow;
            ScanDurationFormatted = "0 dk 00 sn";
            RemainingEtaFormatted = string.Empty;
            ScanStatusText = $"{scanType} taraması işleniyor...";
            _stopwatch.Restart();
            _timer?.Start();
            _isCancellationRequested = false;
            OnPropertyChanged(nameof(ScanResultTitle));
            OnPropertyChanged(nameof(CleanStateTitle));
            OnPropertyChanged(nameof(CleanStateSubtitle));
            OnPropertyChanged(nameof(PauseButtonText));
        }

    }
}
