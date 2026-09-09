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
    /// Tarama görünümü durumunu, ilerleme ölçümlerini, bulunan tehditleri ve
    /// kullanıcı etkileşimlerini yöneten merkezi ViewModel sınıfı.
    /// Mantıksal alt modülleri Sync, Intelligence ve Commands partial dosyalarında genişletilmiştir.
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
        public string ScanResultTitle => _isCancellationRequested ? "Tehdit Taraması İptal Edildi" : "Tehdit Taraması Sonuçları";
        public string CleanStateTitle => _isCancellationRequested ? "Tarama İptal Edildi" : "Sisteminiz temiz";
        public string CleanStateSubtitle => _isCancellationRequested 
            ? $"Tarama kullanıcı tarafından durduruldu. İncelenen {ScannedItemsFormatted} öğede herhangi bir tehdit tespit edilmedi." 
            : "Taranan dosyalarda herhangi bir zararlı kod veya tehdit bulunamadı.";

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
        public string CpuAndRamFormatted => $"CPU: %{CpuUsagePercent:F0} • RAM: {RamUsageMb:F0} MB";
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

        #region 5 Adımlı Kontrol Listesi (Checklist) Göstergeleri
        /// <summary>
        /// 1. Aşama: Bellek ve başlangıç nesneleri taraması tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep1Done;

        /// <summary>
        /// 2. Aşama: Sistem ve sürücü dosyaları denetimi tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep2Done;

        /// <summary>
        /// 3. Aşama: Kullanıcı profili ve indirilen dosyalar taraması tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep3Done;

        /// <summary>
        /// 4. Aşama: Heuristik ve derin PE analizi tamamlandı mı?
        /// </summary>
        [ObservableProperty]
        private bool isStep4Done;

        /// <summary>
        /// 5. Aşama: Sonuç raporlama ve temizleme aşaması etkin mi?
        /// </summary>
        [ObservableProperty]
        private bool isStep5Active = true;
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
        /// ScanViewModel örneğini gerekli servis bağımlılıklarıyla başlatır ve zamanlayıcıları kurar.
        /// </summary>
        public ScanViewModel(
            IScanCoordinatorService? scanCoordinator = null, 
            ISecurityFindingService? findingService = null,
            IQuarantineService? quarantineService = null,
            IAllowlistService? allowlistService = null,
            IWindowsToastNotificationService? toastService = null,
            IScanResourceManager? resourceManager = null,
            ISettingsService? settingsService = null)
        {
            _scanCoordinator = scanCoordinator;
            _findingService = findingService;
            _quarantineService = quarantineService;
            _allowlistService = allowlistService;
            _toastService = toastService;
            _resourceManager = resourceManager;
            _settingsService = settingsService;

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
            HardwareProfileDetail = $"{profile.TotalRamGb:F0} GB RAM için azami {profile.MaxMemoryBudgetMb} MB bellek kotası ve {profile.Concurrency} iş parçacığı tahsis edildi. Arka plan önceliği (BelowNormal) ile sistem donması önlenir.";

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
            System.Windows.Application.Current?.Dispatcher?.Invoke(() =>
            {
                ResetScanState(session.ScanType);
                Views.ActiveScanWindow.ShowScanWindow(this);
            });
        }

        /// <summary>
        /// Yeni bir tarama başlatılmadan önce arayüz durumunu, sayaçları ve süre izleyicilerini sıfırlar.
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
            TotalCount = 0;
            FindingsCount = 0;
            DetectionsCount = 0;
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

        public static string FormatDuration(TimeSpan elapsed)
        {
            if (elapsed < TimeSpan.Zero)
            {
                elapsed = TimeSpan.Zero;
            }

            if (elapsed.TotalHours >= 1)
            {
                return $"{(int)elapsed.TotalHours} sa {elapsed.Minutes:D2} dk {elapsed.Seconds:D2} sn";
            }
            return $"{elapsed.Minutes} dk {elapsed.Seconds:D2} sn";
        }

        public static string FormatEta(double? remainingSeconds, int scanned, int total)
        {
            string counts = total > 0 ? $"({scanned:N0} / {total:N0} dosya)" : $"({scanned:N0} dosya)";
            if (!remainingSeconds.HasValue || remainingSeconds.Value <= 0)
            {
                return $"Kalan: tahmin ediliyor {counts}";
            }

            var ts = TimeSpan.FromSeconds(remainingSeconds.Value);
            if (ts.TotalHours >= 1)
            {
                return $"Kalan: ~{(int)ts.TotalHours} sa {ts.Minutes} dk {ts.Seconds} sn {counts}";
            }
            if (ts.TotalMinutes >= 1)
            {
                return $"Kalan: ~{ts.Minutes} dk {ts.Seconds} sn {counts}";
            }
            return $"Kalan: ~{ts.Seconds} sn {counts}";
        }
    }
}