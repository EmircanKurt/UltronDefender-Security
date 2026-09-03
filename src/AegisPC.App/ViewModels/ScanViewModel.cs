using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Threading;
using AegisPC.Contracts.Services;
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

        private DispatcherTimer? _timer;
        private Stopwatch _stopwatch = new();

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
        /// Tarama başlangıcından bu yana geçen sürenin biçimlendirilmiş metni (ör. 1d 24s).
        /// </summary>
        [ObservableProperty]
        private string scanDurationFormatted = "0d 00s";

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
    }
}