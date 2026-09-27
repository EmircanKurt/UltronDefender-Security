# Ultron Defender (AegisPC) - Kod Tabani ve Klasor Yapisi Raporu

> **Tarih:** 2026-09-02 | **Kapsam:** Cozumdeki 16 proje, tum alt klasorler ve tum .cs dosyalari.

---

## 1. Proje Bazli Ozet Tablosu

| Proje Adi | Toplam .cs Dosyasi | Toplam Satir Sayisi | >=400 Satir Dosya | Katman / Gorevi |
|---|:---:|:---:|:---:|---|
| **AegisPC.Core** | 68 | 1,528 | 0 | Temel modeller, sabitler, enumlar, yollar ve ortak yardimcilar |
| **AegisPC.Contracts** | 72 | 1,769 | 0 | Servis ve motor arayuzleri (IoC/DI sozlesmeleri) |
| **AegisPC.Security** | 70 | 15,104 | 11 | Antivirus/EDR tespit motorlari, tarayicilar, bellek/heuristik analiz |
| **AegisPC.App** | 68 | 7,544 | 1 | WPF UI istemcisi, MVVM ViewModel, View ve converterlar |
| **AegisPC.Infrastructure** | 23 | 2,557 | 0 | Veritabani (SQLite), Windows Security Center, Logging, IPC |
| **AegisPC.Persistence** | 6 | 720 | 0 | Karantina kasasi (Vault), Baslangic ogeleri yonetimi |
| **AegisPC.Service** | 29 | 938 | 0 | Windows Arka Plan Servisi (Daemon worker) |
| **AegisPC.ServiceContracts** | 5 | 88 | 0 | IPC mesaj modelleri ve servis arayuzleri |
| **AegisPC.Diagnostics** | 5 | 514 | 0 | Kilitlenme ve olay gunlugu hata analizi |
| **AegisPC.Performance** | 10 | 1,302 | 0 | Donanim ve surec performans telemetrisi |
| **AegisPC.BrowserSecurity** | 4 | 473 | 0 | Tarayici eklenti ve profil denetleyicisi |
| **AegisPC.Recommendations** | 6 | 458 | 0 | Sistem saglik skoru ve optimizasyon onerileri |
| **AegisPC.Tests** | 48 | 7,367 | 3 | xUnit testleri (Golden Test Suite, EDR senaryolari, birim testler) |
| **AegisPC.ElevatedHelper** | 1 | 336 | 0 | UAC ile calisan yuksek yetkili yardimci arac |
| **AegisPC.LiveTest** | 1 | 140 | 0 | Canli test konsol araci |
| **AegisPC.Uninstaller** | 2 | 227 | 0 | Kaldirma ve kayit defteri/WMI temizleme araci |
| **GENEL TOPLAM** | **418** | **41,065** | **15** | **Tum Cozum (Solution)** |

---

## 2. Bolunmesi Gereken Dosyalar (>= 400 Satir Siniri)

> AI_GUIDELINES.md Kural 4.3 (Dosyalar 500 satiri gecmesin) ve 400 satir moduler mimari ilkelerine gore acilen bolunmesi gereken dosyalar:

| # | Dosya Adi | Proje | Satir Sayisi | Onem Derecesi | Ihlal Nedeni / Oneri |
|---|---|---|:---:|---|---|
| 1 | `RealTimeProtectionEngine.cs` | AegisPC.Security | **758** | KRITIK (>=600 satir) | Asiri monolitik yapi; 2 veya daha fazla alt servise bolunmeli |
| 2 | `RansomwareProtectionEngine.cs` | AegisPC.Security | **719** | KRITIK (>=600 satir) | Asiri monolitik yapi; 2 veya daha fazla alt servise bolunmeli |
| 3 | `FileScannerService.cs` | AegisPC.Security | **698** | KRITIK (>=600 satir) | Asiri monolitik yapi; 2 veya daha fazla alt servise bolunmeli |
| 4 | `SecurityTestingLabSuite.cs` | AegisPC.Tests | **627** | KRITIK (>=600 satir) | Asiri monolitik yapi; 2 veya daha fazla alt servise bolunmeli |
| 5 | `StartupSecuritySweepService.cs` | AegisPC.Security | **599** | YUKSEK (>=500 satir) | AI_GUIDELINES Kural 4.3 dogrudan ihlal edildi |
| 6 | `MsrtRemediationEngine.cs` | AegisPC.Security | **562** | YUKSEK (>=500 satir) | AI_GUIDELINES Kural 4.3 dogrudan ihlal edildi |
| 7 | `QuarantineService.cs` | AegisPC.Security | **562** | YUKSEK (>=500 satir) | AI_GUIDELINES Kural 4.3 dogrudan ihlal edildi |
| 8 | `DnsProtectionService.cs` | AegisPC.Security | **507** | YUKSEK (>=500 satir) | AI_GUIDELINES Kural 4.3 dogrudan ihlal edildi |
| 9 | `DeepPeAnalyzer.cs` | AegisPC.Security | **506** | YUKSEK (>=500 satir) | AI_GUIDELINES Kural 4.3 dogrudan ihlal edildi |
| 10 | `TransactionalQuarantineEngine.cs` | AegisPC.Security | **469** | ORTA (400-499 satir) | 400 satir hedefini asiyor; alt modullere ayrilabilir |
| 11 | `BehaviorEngine.cs` | AegisPC.Security | **453** | ORTA (400-499 satir) | 400 satir hedefini asiyor; alt modullere ayrilabilir |
| 12 | `StartupSecuritySweepTests.cs` | AegisPC.Tests | **426** | ORTA (400-499 satir) | 400 satir hedefini asiyor; alt modullere ayrilabilir |
| 13 | `MemoryPatternScanner.cs` | AegisPC.Security | **411** | ORTA (400-499 satir) | 400 satir hedefini asiyor; alt modullere ayrilabilir |
| 14 | `RealBrowserAndStressValidationTests.cs` | AegisPC.Tests | **408** | ORTA (400-499 satir) | 400 satir hedefini asiyor; alt modullere ayrilabilir |
| 15 | `DashboardViewModel.cs` | AegisPC.App | **401** | ORTA (400-499 satir) | 400 satir hedefini asiyor; alt modullere ayrilabilir |

---

## 3. AI_GUIDELINES.md Uyumsuzluklari ve Mimari Ihlal Analizi

### 3.1. Kural 4.3 Dosya Boyutu Siniri Ihlalleri (>500 Satir)
Projede 500 satir sinirini asan toplam **9 adet** dosya bulunmaktadir:

- `AegisPC.Security/RealTime\RealTimeProtectionEngine.cs`: **758 satir**
- `AegisPC.Security/RealTime\RansomwareProtectionEngine.cs`: **719 satir**
- `AegisPC.Security/Scanning\FileScannerService.cs`: **698 satir**
- `AegisPC.Tests/SecurityTestingLabSuite.cs`: **627 satir**
- `AegisPC.Security/Scanning\StartupSecuritySweepService.cs`: **599 satir**
- `AegisPC.Security/Scanning\MsrtRemediationEngine.cs`: **562 satir**
- `AegisPC.Security/Scanning\QuarantineService.cs`: **562 satir**
- `AegisPC.Security/RealTime\DnsProtectionService.cs`: **507 satir**
- `AegisPC.Security/PE\DeepPeAnalyzer.cs`: **506 satir**

### 3.2. Kural 4.1 & 4.2 Tek Sorumluluk (Single Responsibility) ve God Object Ihlalleri
1. **`RealTimeProtectionEngine.cs` (758 satir):** Olay dinleme, kuyruk yonetimi, dosya kararliligi bekleme, risk puanlama entegrasyonu, bildirim, surec oldurme ve karantina islemlerini tek sinifta barindiriyor.
1. **`RansomwareProtectionEngine.cs` (719 satir):** Tuzak (canary) dosya olusturma/izleme, dosya uzanti filtresi, Shannon entropi patlamasi tespiti, korumali klasor erisim korumasi ve surec sonlandirmayi ayni govdede yurutuyor.
1. **`FileScannerService.cs` (698 satir):** Rekursif dosya tarama, BoundedChannel uretici-tuketici dongusu, hash kontrolu, PUP analizi, imza sorgusu ve karantina cagrilarini tek basina yonetiyor.
1. **`StartupSecuritySweepService.cs` (599 satir):** Windows baslangic klasoru, Run registry anahtarlari, servisler, gorev zamanlayici denetimleri ve Downloads klasorunu monolitik bir dongude tariyor.
1. **`QuarantineService.cs` (562 satir):** AES-GCM sifreleme/cozme, guvenli dosya silme (zero-wipe), veritabani indeks senkronizasyonu ve olay tetiklemeyi tek sinifta topluyor.
1. **`MsrtRemediationEngine.cs` (562 satir):** Cok sayida bagimsiz registry anahtari temizligi, surec sonlandirma ve zararli izi temizligini ayrilmamis dev bir akisla yapiyor.
1. **`DeepPeAnalyzer.cs` (506 satir):** MZ basligi, PE Header, Data Directories, Sections, TLS callback, Rich Header ve Authenticode sertifika cozumlemesini tek sinifta yurutuyor.
1. **`DnsProtectionService.cs` (507 satir):** Ag bagdastirici WMI sorgusu, IPv4/IPv6 DNS degistirme, Hosts dosyasi yonetimi ve DNS telemetrisini tek sinifta topluyor.

### 3.3. Kural 7: Magic String ve Ad Bazli Karar Yasagi Ihlalleri
- **`RiskScoringEngine.cs` (Satir 16-20):** `ExactPupKeywords` (crack, keygen, activator, repack, hacktool, trainer, cheat, kmsauto, kmspico, hwidgen, injector, spoofer) ad bazli bir hashset kullanmaktadir. Kural 7.1 e gore dosya adina gore guvenlik karari vermek yasaktir; bu kararlar hash, PE davranisi veya sertifikaya dayanmalidir.
- **`GameCrackClassifier.cs`:** Dosya adinda steam_api.dll, codex64.dll, emp.dll aramaktadir.
- **`EtwProcessMonitorService.cs`:** Komut satiri regex kaliplarina gore terminate islemi yapmaktadir (EDR davranisi oldugundan kabul edilebilir olsa da kurallarin merkezi konfigurasyna tasinmasi onerilir).

### 3.4. Olu Kod ve Bos Sinif Ihlalleri
- **`AegisPC.Service/RealTime/EtwProcessMonitor.cs` (7 satir):** Ici tamamen bos bir stub siniftir. Gercek calisan servis `AegisPC.Security` icindedir.
- **`AegisPC.Service` icerisindeki stub siniflar:** `CloudThreatIntelligence.cs` (4 satir), `SampleSubmissionService.cs` (4 satir), `KernelBridge.cs` (4 satir), `ResourceThrottler.cs` (4 satir) gibi bircok dosya bos stub govdesinden olusmaktadir.

---

## 4. Tam Proje, Klasor ve Dosya Agaci

### [AegisPC.Core]/

```text
AegisPC.Core/
  [Configuration]/
    FeatureFlags.cs (36 satir)
  [Constants]/
    AppConstants.cs (13 satir)
    CriticalProcesses.cs (19 satir)
    KnownPaths.cs (19 satir)
  [Enums]/
    AuditAction.cs (2 satir)
    AuditResult.cs (2 satir)
    BrowserType.cs (13 satir)
    ConfidenceLevel.cs (2 satir)
    CrashEventType.cs (2 satir)
    EventSeverity.cs (2 satir)
    FindingCategory.cs (20 satir)
    FindingStatus.cs (2 satir)
    ImpactLevel.cs (2 satir)
    QuarantineStatus.cs (2 satir)
    RealTimeEventType.cs (13 satir)
    RealTimePolicyAction.cs (13 satir)
    RealTimeVerdict.cs (12 satir)
    RecommendationCategory.cs (2 satir)
    RecommendationStatus.cs (2 satir)
    RiskLevel.cs (2 satir)
    ScanStatus.cs (2 satir)
    ScanType.cs (2 satir)
    ThemeMode.cs (2 satir)
    ThreatCategory.cs (18 satir)
  [Helpers]/
    DiskHardwareHelper.cs (126 satir)
    FileSizeHelper.cs (25 satir)
    GameCrackClassifier.cs (97 satir)
    MotwAnalyzer.cs (93 satir)
    ParentalControlService.cs (65 satir)
    PathHelper.cs (107 satir)
    ScanScheduleEvaluator.cs (29 satir)
    TimeHelper.cs (22 satir)
    ValidationHelper.cs (12 satir)
  [Localization]/
    LocalizationService.cs (111 satir)
  [Models]/
    AllowedRansomwareApplication.cs (15 satir)
    AllowlistEntry.cs (15 satir)
    AppUsageRecord.cs (13 satir)
    AuditLogEntry.cs (17 satir)
    BehaviorAlert.cs (15 satir)
    BlockedConnection.cs (16 satir)
    BrowserExtension.cs (19 satir)
    BrowserProfile.cs (12 satir)
    CloudReputation.cs (15 satir)
    CrashEvent.cs (21 satir)
    CrashReport.cs (14 satir)
    DownloadAnalysis.cs (16 satir)
    FileAnalysisResult.cs (29 satir)
    HealthScore.cs (17 satir)
    InstalledApplication.cs (19 satir)
    NetworkConnection.cs (14 satir)
    ParentalRule.cs (16 satir)
    PerformanceSample.cs (17 satir)
    ProcessInfo.cs (26 satir)
    ProcessTreeNode.cs (10 satir)
    ProtectedFolder.cs (18 satir)
    QuarantineEntry.cs (19 satir)
    RansomwareEvent.cs (15 satir)
    Recommendation.cs (21 satir)
    ReputationResult.cs (14 satir)
    ScanProgress.cs (20 satir)
    ScanResult.cs (20 satir)
    SecurityFinding.cs (27 satir)
    SecurityIncident.cs (67 satir)
    SignatureInfo.cs (16 satir)
    StartupItem.cs (20 satir)
    TimelineEntry.cs (14 satir)
    UpdateManifest.cs (14 satir)
    WindowsEventEntry.cs (16 satir)
```

### [AegisPC.Contracts]/

```text
AegisPC.Contracts/
  [AntiEvasion]/
    AntiEvasionEvaluation.cs (20 satir)
    AntiEvasionTechnique.cs (17 satir)
    IAntiEvasionDetector.cs (14 satir)
    IMemoryPatternScanner.cs (17 satir)
    MemoryScanVerdict.cs (20 satir)
  [Archive]/
    ArchiveSafetyLimits.cs (11 satir)
    ArchiveScanVerdict.cs (24 satir)
    ISecureArchiveEngine.cs (16 satir)
  [Behavior]/
    AttackChainCorrelationResult.cs (27 satir)
    IAttackChainCorrelator.cs (18 satir)
    IProcessInjectionDetector.cs (12 satir)
    IProcessLineageTracker.cs (19 satir)
    ProcessInjectionEvaluation.cs (31 satir)
    ProcessNode.cs (24 satir)
  [Caching]/
    IScanCacheService.cs (53 satir)
  [Detection]/
    DetectionContext.cs (81 satir)
    IDetectionHub.cs (26 satir)
    SecurityEvidence.cs (83 satir)
  [Events]/
    PerformanceAlertEvent.cs (12 satir)
    ProcessChangedEvent.cs (9 satir)
    ScanProgressEvent.cs (8 satir)
    SecurityFindingEvent.cs (10 satir)
  [Kernel]/
    IKernelMinifilterContracts.cs (27 satir)
    KernelFileTelemetryEvent.cs (43 satir)
    KernelIpcModels.cs (35 satir)
  [Network]/
    NetworkContracts.cs (63 satir)
  [PE]/
    IDeepPeAnalyzer.cs (22 satir)
    PeCertificateDetail.cs (48 satir)
    PeDeepAnalysisResult.cs (53 satir)
    PeRichHeaderEntry.cs (37 satir)
    PeSectionDetail.cs (49 satir)
  [Safety]/
    ICanonicalPathResolver.cs (19 satir)
    IProtectedPathGuard.cs (27 satir)
    IReparsePointGuard.cs (19 satir)
    ITransactionalQuarantine.cs (21 satir)
    ProtectedPathCategory.cs (18 satir)
    ProtectedPathEvaluation.cs (19 satir)
    QuarantineTransactionModels.cs (52 satir)
    ReparsePointInfo.cs (20 satir)
    ReparsePointType.cs (14 satir)
  [SelfProtection]/
    SelfProtectionContracts.cs (43 satir)
  [Services]/
    IAllowlistService.cs (15 satir)
    IAmsiScanService.cs (32 satir)
    IAuditLogService.cs (14 satir)
    IBehaviorEngine.cs (19 satir)
    IBrowserSecurityScanner.cs (13 satir)
    ICorrelationEngine.cs (11 satir)
    ICrashAnalyzer.cs (14 satir)
    IDatabaseService.cs (12 satir)
    IDnsProtectionService.cs (46 satir)
    IElevationService.cs (10 satir)
    IEtwProcessMonitorService.cs (38 satir)
    IFileScanner.cs (16 satir)
    IHashService.cs (10 satir)
    INetworkMonitor.cs (12 satir)
    INotificationAggregator.cs (17 satir)
    INotificationService.cs (11 satir)
    IPerformanceMonitor.cs (14 satir)
    IProcessMonitor.cs (13 satir)
    IQuarantineService.cs (16 satir)
    IRecommendationEngine.cs (14 satir)
    IReputationService.cs (10 satir)
    IRiskScoringEngine.cs (12 satir)
    IScanCoordinatorService.cs (32 satir)
    ISecureStorageService.cs (11 satir)
    ISecurityFindingService.cs (18 satir)
    ISettingsService.cs (12 satir)
    ISignatureVerifier.cs (10 satir)
    IStartupAnalyzer.cs (12 satir)
    IStartupSecuritySweepService.cs (80 satir)
    IWebShieldService.cs (30 satir)
    IWindowsEventAnalyzer.cs (14 satir)
```

### [AegisPC.Security]/

```text
AegisPC.Security/
  [AntiEvasion]/
    AmsiIntegrityChecker.cs (48 satir)
    AntiEvasionDetector.cs (278 satir)
    AntiEvasionDetectorPlugin.cs (52 satir)
    EtwBlindingDetector.cs (38 satir)
    MemoryPatternScanner.cs (411 satir) [!] >=400 SATIR
    ProcessHollowingDetector.cs (30 satir)
  [Archive]/
    ArchiveDetectorPlugin.cs (58 satir)
    SecureArchiveEngine.cs (205 satir)
  [Behavior]/
    AttackChainCorrelator.cs (123 satir)
    ProcessInjectionDetector.cs (137 satir)
    ProcessLineageTracker.cs (149 satir)
  [Caching]/
    MultiLayerScanCache.cs (259 satir)
  [Common]/
    SecObfuscator.cs (19 satir)
  [Detection]/
    DetectionHub.cs (341 satir)
    DetectionHubFactory.cs (58 satir)
  [Detection/Detectors]/
    AuthenticodeDetector.cs (145 satir)
    EntropyDetector.cs (82 satir)
    HashSignatureDetector.cs (85 satir)
    LocationReputationDetector.cs (195 satir)
    MemoryBehaviorDetector.cs (106 satir)
    NetworkBehaviorDetector.cs (44 satir)
    PeStaticDetector.cs (98 satir)
    PersistenceDetector.cs (64 satir)
    ProcessBehaviorDetector.cs (60 satir)
    ScriptHeuristicDetector.cs (103 satir)
  [Kernel]/
    KernelGatingEngine.cs (104 satir)
    KernelIpcService.cs (81 satir)
    KernelMinifilterTelemetryEngine.cs (84 satir)
  [Network]/
    NetworkProcessCorrelator.cs (126 satir)
  [Notifications]/
    NotificationAggregator.cs (110 satir)
  [PE]/
    DeepPeAnalyzer.cs (506 satir) [!] >=400 SATIR
    DeepPeDetector.cs (222 satir)
  [RealTime]/
    BackgroundProtectionService.cs (362 satir)
    BehaviorEngine.cs (453 satir) [!] >=400 SATIR
    DnsProtectionService.cs (507 satir) [!] >=400 SATIR
    EtwProcessMonitorService.cs (386 satir)
    GameCrackWatchdogShield.cs (156 satir)
    IRealTimeProtectionEngine.cs (80 satir)
    NormalizedFileEvent.cs (67 satir)
    ProcessMitigationHelper.cs (178 satir)
    RansomwareProtectionEngine.cs (719 satir) [!] >=400 SATIR
    RealTimeActivityEvent.cs (91 satir)
    RealTimeProtectionEngine.Watchers.cs (230 satir)
    RealTimeProtectionEngine.cs (758 satir) [!] >=400 SATIR
    RealTimeVerdictResult.cs (97 satir)
  [Reputation]/
    ReputationService.cs (39 satir)
  [Safety]/
    CanonicalPathResolver.cs (154 satir)
    ProtectedPathGuard.cs (195 satir)
    ReparsePointGuard.cs (239 satir)
    TransactionalQuarantineEngine.cs (469 satir) [!] >=400 SATIR
  [Scanning]/
    AllowlistService.cs (134 satir)
    AmsiScanService.cs (263 satir)
    ArchiveSafetyScanner.cs (217 satir)
    EntropyCalculator.cs (79 satir)
    FileScannerService.cs (698 satir) [!] >=400 SATIR
    HashService.cs (53 satir)
    MalwareSignatureDatabase.cs (265 satir)
    MsrtRemediationEngine.cs (562 satir) [!] >=400 SATIR
    PeAnalyzer.cs (178 satir)
    QuarantineService.cs (562 satir) [!] >=400 SATIR
    RiskScoringEngine.cs (182 satir)
    ScanCoordinatorService.cs (247 satir)
    ScanFilterPolicy.cs (272 satir)
    SecurityFindingService.cs (88 satir)
    SignatureVerifier.cs (203 satir)
    StartupSecuritySweepService.cs (599 satir) [!] >=400 SATIR
    ThreatSignatureDatabase.cs (381 satir)
    WebShieldService.cs (361 satir)
  [SelfDefense]/
    SelfDefenseManager.cs (64 satir)
  [SelfProtection]/
    SelfProtectionEngine.cs (95 satir)
```

### [AegisPC.App]/

```text
AegisPC.App/
  App.xaml.cs (335 satir)
  AssemblyInfo.cs (10 satir)
  MainWindow.xaml.cs (159 satir)
  Program.cs (263 satir)
  [Converters]/
    BoolToStatusTextConverter.cs (34 satir)
    BoolToVisibilityConverter.cs (53 satir)
    BytesToHumanReadableConverter.cs (26 satir)
    NullToBoolConverter.cs (21 satir)
    PercentToColorConverter.cs (24 satir)
    RiskLevelToColorConverter.cs (28 satir)
    SecurityStatusToColorConverter.cs (105 satir)
  [Services]/
    AppThemeManager.cs (196 satir)
    NotificationService.cs (47 satir)
    ServiceIpcClient.cs (162 satir)
    ShellContextMenuService.cs (93 satir)
    SystemTrayService.cs (182 satir)
    WindowsToastNotificationService.cs (192 satir)
  [Startup]/
    AutoStartHelper.cs (72 satir)
    ServiceRegistration.cs (182 satir)
  [ViewModels]/
    ApplicationsViewModel.cs (126 satir)
    BrowserSecurityViewModel.cs (89 satir)
    CrashAnalysisViewModel.cs (91 satir)
    DashboardViewModel.Actions.cs (326 satir)
    DashboardViewModel.Telemetry.cs (371 satir)
    DashboardViewModel.cs (401 satir) [!] >=400 SATIR
    HistoryViewModel.cs (84 satir)
    IncidentCenterViewModel.cs (251 satir)
    MainViewModel.cs (8 satir)
    NetworkProtectionViewModel.cs (264 satir)
    NetworkViewModel.cs (85 satir)
    ParentalControlsViewModel.cs (8 satir)
    PerformanceViewModel.cs (255 satir)
    ProcessListViewModel.cs (137 satir)
    QuarantineViewModel.cs (132 satir)
    RansomwareShieldViewModel.cs (279 satir)
    RealTimeMonitorViewModel.cs (77 satir)
    RecommendationsViewModel.cs (85 satir)
    ScanViewModel.Commands.cs (249 satir)
    ScanViewModel.Intelligence.cs (133 satir)
    ScanViewModel.Sync.cs (166 satir)
    ScanViewModel.cs (275 satir)
    SecurityViewModel.cs (137 satir)
    SettingsViewModel.cs (296 satir)
    StartupManagerViewModel.cs (140 satir)
    WindowsEventsViewModel.cs (93 satir)
  [ViewModels/Models]/
    SelectableThreatModel.cs (47 satir)
  [Views]/
    ActiveScanWindow.xaml.cs (102 satir)
    ApplicationsView.xaml.cs (17 satir)
    BrowserSecurityView.xaml.cs (17 satir)
    CrashAnalysisView.xaml.cs (17 satir)
    DashboardView.xaml.cs (29 satir)
    HistoryView.xaml.cs (17 satir)
    IncidentCenterView.xaml.cs (22 satir)
    NetworkProtectionView.xaml.cs (24 satir)
    NetworkView.xaml.cs (17 satir)
    ParentalControlsView.xaml.cs (14 satir)
    PerformanceView.xaml.cs (53 satir)
    ProcessListView.xaml.cs (28 satir)
    QuarantineView.xaml.cs (17 satir)
    RansomwareShieldView.xaml.cs (40 satir)
    RealTimeMonitorView.xaml.cs (17 satir)
    RecommendationsView.xaml.cs (17 satir)
    ScanView.xaml.cs (42 satir)
    SecurityView.xaml.cs (17 satir)
    SettingsView.xaml.cs (27 satir)
    StartupManagerView.xaml.cs (17 satir)
    ToastNotificationWindow.xaml.cs (187 satir)
    WindowsEventsView.xaml.cs (17 satir)
```

### [AegisPC.Infrastructure]/

```text
AegisPC.Infrastructure/
  AuditLogService.cs (65 satir)
  WindowsSecurityRegistrationService.cs (180 satir)
  [Configuration]/
    AppSettings.cs (32 satir)
    SettingsService.cs (104 satir)
  [Database]/
    DatabaseMigration.cs (76 satir)
    DatabaseService.cs (357 satir)
    RetentionService.cs (57 satir)
  [Database/Repositories]/
    ApplicationInventoryRepository.cs (128 satir)
    AuditLogRepository.cs (103 satir)
    CrashEventRepository.cs (104 satir)
    FileHashRepository.cs (76 satir)
    PerformanceSampleRepository.cs (83 satir)
    QuarantineRepository.cs (127 satir)
    RecommendationRepository.cs (141 satir)
    ScanHistoryRepository.cs (111 satir)
    SecurityFindingRepository.cs (150 satir)
    StartupItemRepository.cs (127 satir)
    WindowsEventRepository.cs (102 satir)
  [Elevation]/
    ElevationService.cs (63 satir)
  [Ipc]/
    SecureNamedPipeServer.cs (118 satir)
  [Kernel]/
    KernelIpcService.cs (131 satir)
  [Logging]/
    SerilogConfiguration.cs (49 satir)
  [SecureStorage]/
    DpapiSecureStorageService.cs (73 satir)
```

### [AegisPC.Persistence]/

```text
AegisPC.Persistence/
  [Quarantine]/
    VaultManager.cs (133 satir)
  [Startup]/
    RegistryStartupScanner.cs (171 satir)
    StartupAnalyzerService.cs (94 satir)
    StartupFolderScanner.cs (48 satir)
    StartupManagementService.cs (208 satir)
    TaskSchedulerScanner.cs (66 satir)
```

### [AegisPC.Service]/

```text
AegisPC.Service/
  Program.cs (96 satir)
  [Amsi]/
    AmsiScanService.cs (34 satir)
  [Behavioral]/
    BehaviorAnalyzer.cs (7 satir)
    BehaviorRule.cs (6 satir)
  [Cloud]/
    CloudThreatIntelligence.cs (4 satir)
    SampleSubmissionService.cs (4 satir)
  [DriverBridge]/
    KernelBridge.cs (4 satir)
  [IPC]/
    NamedPipeServer.cs (259 satir)
  [Network]/
    DnsFilterService.cs (7 satir)
    NetworkProtectionService.cs (7 satir)
    ThreatFeedManager.cs (7 satir)
  [Optimization]/
    ResourceThrottler.cs (4 satir)
    ScanCacheService.cs (4 satir)
  [Parental]/
    AppUsageTracker.cs (4 satir)
    ParentalControlService.cs (65 satir)
  [Ransomware]/
    CanaryFileMonitor.cs (7 satir)
    EntropyBurstDetector.cs (7 satir)
    RansomwareShield.cs (7 satir)
  [RealTime]/
    EtwImageLoadMonitor.cs (7 satir)
    EtwProcessMonitor.cs (7 satir)
    RealTimeFileMonitor.cs (41 satir)
  [Scheduler]/
    IdleDetector.cs (4 satir)
    ScanScheduler.cs (82 satir)
  [SmartScreen]/
    DownloadGuard.cs (4 satir)
    MotwAnalyzer.cs (4 satir)
  [Update]/
    AutoUpdateService.cs (4 satir)
    ThreatFeedUpdater.cs (140 satir)
    YaraRuleManager.cs (4 satir)
  [Workers]/
    ProtectionWorker.cs (108 satir)
```

### [AegisPC.ServiceContracts]/

```text
AegisPC.ServiceContracts/
  IServiceIpcClient.cs (20 satir)
  [IpcMessages]/
    ProtectionStatus.cs (17 satir)
    ScanProgressIpc.cs (17 satir)
    ServiceCommand.cs (17 satir)
    ThreatNotification.cs (17 satir)
```

### [AegisPC.Diagnostics]/

```text
AegisPC.Diagnostics/
  [Correlation]/
    CorrelationEngine.cs (64 satir)
  [Crash]/
    CrashAnalyzer.cs (77 satir)
    CrashReportBuilder.cs (87 satir)
  [EventLog]/
    EventPatternMatcher.cs (112 satir)
    WindowsEventAnalyzer.cs (174 satir)
```

### [AegisPC.Performance]/

```text
AegisPC.Performance/
  [Hardware]/
    HardwareInfoService.cs (249 satir)
  [Monitoring]/
    CpuMonitor.cs (59 satir)
    DiskMonitor.cs (37 satir)
    MemoryMonitor.cs (47 satir)
    PerformanceMonitorService.cs (180 satir)
  [Network]/
    NetworkMonitorService.cs (69 satir)
    TcpTableInterop.cs (120 satir)
  [Process]/
    ProcessMonitorService.cs (264 satir)
    ProcessTerminationService.cs (226 satir)
    ProcessTreeBuilder.cs (51 satir)
```

### [AegisPC.BrowserSecurity]/

```text
AegisPC.BrowserSecurity/
  [Applications]/
    ApplicationInventoryScanner.cs (99 satir)
  [Browser]/
    BrowserSecurityService.cs (79 satir)
    ChromiumExtensionScanner.cs (211 satir)
    FirefoxSecurityScanner.cs (84 satir)
```

### [AegisPC.Recommendations]/

```text
AegisPC.Recommendations/
  [AiExplanation]/
    AiExplanationService.cs (32 satir)
  [Engine]/
    HealthScoringEngine.cs (119 satir)
    RecommendationEngine.cs (127 satir)
  [Rules]/
    PerformanceRule.cs (68 satir)
    SecurityRule.cs (68 satir)
    StabilityRule.cs (44 satir)
```

### [AegisPC.Tests]/

```text
AegisPC.Tests/
  AdvancedSecurityEngineTests.cs (200 satir)
  AmsiAndWscTests.cs (80 satir)
  AntiEvasionTests.cs (162 satir)
  ArchiveSafetyScannerTests.cs (92 satir)
  AssemblyInfo.cs (5 satir)
  AuditScenarioVerificationTests.cs (393 satir)
  BehaviorAnalyzerTests.cs (118 satir)
  BehaviorChainTests.cs (238 satir)
  CriticalProcessesTests.cs (24 satir)
  DeepPeAnalyzerTests.cs (290 satir)
  DesktopFullScanTests.cs (130 satir)
  DiContainerIntegrityTests.cs (61 satir)
  EntropyCalculatorTests.cs (35 satir)
  EventPatternMatcherTests.cs (45 satir)
  EvidenceModelAndHubTests.cs (356 satir)
  GameCrackWatchdogTests.cs (89 satir)
  GoldenTestSuite.cs (306 satir)
  InstantFileArrivalProtectionTests.cs (144 satir)
  KernelMinifilterTests.cs (146 satir)
  KeyloggerDetectionTests.cs (76 satir)
  LocalizationTests.cs (35 satir)
  MotwAnalyzerTests.cs (43 satir)
  MultiLayerScanCacheTests.cs (164 satir)
  NetworkProcessCorrelatorTests.cs (89 satir)
  NetworkProtectionTests.cs (71 satir)
  NotificationAggregatorTests.cs (110 satir)
  ParentalControlTests.cs (42 satir)
  PathHelperTests.cs (23 satir)
  PerformanceBenchmarkingRunner.cs (87 satir)
  PupScoringTests.cs (93 satir)
  QuarantineVaultTests.cs (61 satir)
  RansomwareProtectionTests.cs (157 satir)
  RansomwareShieldTests.cs (131 satir)
  RealBrowserAndStressValidationTests.cs (408 satir) [!] >=400 SATIR
  RealTimeProtectionEndToEndTests.cs (222 satir)
  RealTimeProtectionTests.cs (306 satir)
  RealWorldVerificationRunner.cs (185 satir)
  RiskScoringEngineTests.cs (52 satir)
  SafetyGuardTests.cs (172 satir)
  ScanSchedulerTests.cs (54 satir)
  ScoringRegressionTests.cs (222 satir)
  SecureArchiveTests.cs (186 satir)
  SecurityBenchmarkTests.cs (166 satir)
  SecurityTestingLabSuite.cs (627 satir) [!] >=400 SATIR
  SelfProtectionTests.cs (47 satir)
  SetupDiagnostics.cs (109 satir)
  StartupSecuritySweepTests.cs (426 satir) [!] >=400 SATIR
  WebShieldTests.cs (89 satir)
```

### [AegisPC.ElevatedHelper]/

```text
AegisPC.ElevatedHelper/
  Program.cs (336 satir)
```

### [AegisPC.LiveTest]/

```text
AegisPC.LiveTest/
  Program.cs (140 satir)
```

### [AegisPC.Uninstaller]/

```text
AegisPC.Uninstaller/
  App.xaml.cs (8 satir)
  MainWindow.xaml.cs (219 satir)
```
