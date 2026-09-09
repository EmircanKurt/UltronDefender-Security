# 📜 CHANGELOG — ULTRON DEFENDER TOTAL SECURITY

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.4.0] - 2026-09-08

### UI/UX & Dynamic Theme Modernization, Scan Tuning & Real-Time Security Alignment
* **GÖREV 1 — Sayfa Geçiş Animasyonları:** `MainWindow.xaml.cs` içerisinde `NavigationView.Navigated` (`RootNavigation.Navigated`) olayı üzerinden merkezi, tek noktadan içerik geçiş animasyonu uygulandı. Her sayfa değişiminde gelen görünüme 180 ms süreli opaklık (0→1) ve 12 px yukarı kayma (`TranslateTransform.Y: 12→0`) animasyonu (`CubicEase EasingMode=EaseOut`) eklendi. Windows `SystemParameters.TurnOnAnimations` ve `AppSettings.ReduceMotion` erişilebilirlik ayarları kontrol edilerek hareket azaltma modu desteklendi.
* **GÖREV 2 — Açılış Animasyonu (Splash):** `#0D0D0D` koyu zemin üzerinde logonun merkezde yer aldığı, 1.5–2 saniye süreli zarif açılış penceresi (`SplashWindow.xaml` / `.xaml.cs`) tasarlandı. İnce belirsiz (indeterminate) yükleme çubuğu, yumuşak logo parlaması ve 250 ms fade-out kapanış animasyonu ile tamamlandı. DI konteynerine transient olarak kaydedildi ve `App.xaml.cs` üzerinden ana pencere öncesi sorunsuz gösterim sağlandı.
* **GÖREV 3 — Süreç Yöneticisi Güncellemesi & GPU Desteği:**
  - `ProcessListViewModel` ilk açılışta süreçleri RAM tüketimine göre azalan sırada (`OrderByDescending(p => p.MemoryBytes)`) listeler.
  - Hızlı filtreleme için 3 adet çip eklendi: "En Çok RAM" (>500 MB), "En Çok CPU" (>%5), "GPU" (>%0 GPU kullanımı).
  - Süreç sorgulamaları `IProcessMonitor.GetProcessesBatch` üzerinden toplu olarak alınır ve 2 saniyelik hareketli ortalama (`ProcessMovingAverage`) ile CPU/GPU dalgalanmaları yumuşatılır.
  - `PerformanceCounter` tabanlı `GPU Engine` sayaç sorgulaması sanal makinelerde (VM), RDP oturumlarında veya GPU sayacı bulunmayan ortamlarda çökmeyecek şekilde güvenli (try/catch + Serilog trace) olarak kümelendirildi.
* **GÖREV 4 — Tarayıcı Güvenliği Dark Mode & Metin İyileştirmesi:** `BrowserSecurityView.xaml` içindeki eklenti listesi DataGrid/ListBox görünümü `DynamicResource` renk paletine (`BrushCardBg`, `BrushCardBorder`, `#262626` hover/seçim zeminleri) bağlandı. "Açıklama yok" veya "MSG_description" gibi boş/yer tutucu metinler `DescriptionVisibilityConverter` ile arayüzden gizlendi; yalnızca gerçek açıklamalar gösterilecek şekilde güncellendi.
* **GÖREV 5 — Tarama Penceresi Renk Dili & Kotanın Birleştirilmesi:**
  - `ActiveScanWindow.xaml` içerisindeki tüm ilerleme bileşenleri (ProgressBar, PulseIndicator, "Dosya sistemini tara" metni, lazer animasyon çizgisi, ETA/Kalan Süre) varsayılan olarak güvenli yeşil renkte (`BrushStatusSafe`) çalışır.
  - Yalnızca en az bir tehdit algılandığında (`HasFindings == true`) tespit sayısı rozeti ve etiketi kırmızı renge (`BrushStatusDanger`) dönüşür.
  - Tarama tamamlandığında 0 bulguda yeşil onay simgesi ve "Sisteminiz temiz" başlığı; >0 bulguda kırmızı özet kartı, "Karantinaya Al" birincil butonu ve "Müdahale" sütununda aksiyon bilgisi gösterilir.
  - Kota metni "X/Y çekirdek, Z GB RAM" formatında `ScanQueueCoordinator.ActiveResourceSummary` statik alanı üzerinden `AdaptiveScanResourceManager` ile tam senkronize edildi.
* **GÖREV 6 — Tarama Başlangıcında Kaynak Profili Seçim Diyaloğu & RAM Ayarı:**
  - Hızlı veya Tam Tarama başlatıldığında `ScanResourceSelectionDialog` modal penceresi görüntülenir: "🌱 Sakin (~1 GB RAM, düşük CPU)", "⚖️ Dengeli (RAM'in 1/3'ü)", "🚀 Tam Güç (Tüm çekirdekler)".
  - "Tercihimi hatırla ve bir daha sorma" seçeneği `AppSettings.RememberScanResourceMode` ve `ScanResourceMode` alanlarına kaydedilir.
  - Seçilen mod `AdaptiveScanResourceManager.SetMode()` fonksiyonuna iletilir.
  - RAM bütçesi insani okunabilir formatta gösterilir ("16 GB RAM'in ~5.3 GB'ı kullanılabilir").
* **GÖREV 7 — "Uyarıldı" Bulguları ile Karantina Tutarsızlığı & Otomatik Güvenlik Politikası:**
  - `RealTimeVerdictProcessor` ve `RealTimeProtectionEngine` eşik değerleri hizalandı: Risk Skoru >= 85 → `BlockAndQuarantine`, 60–84 → `Warn`.
  - `ScanCoordinatorService`, tarama sonucundaki Risk Skoru >= 85 olan tehditleri `IQuarantineService` üzerinden otomatik olarak karantinaya alır, bulgu durumunu `FindingStatus.Resolved` olarak günceller ve `IAuditLogService`'e `AuditAction.FileQuarantined` kaydı işler.
  - 60–84 arasındaki şüpheli bulgular diskten silinmez, "Uyarıldı" olarak işaretlenir ve denetim kaydı oluşturulur.
  - Windows Toast bildirimlerine tıklandığında: 60–84 uyarıları doğrudan `IncidentCenterView` (Olay Merkezi) sayfasına, karantina bildirimleri (>= 85) ise `QuarantineView` sayfasına yönlendirilir.
  - `tests/AegisPC.Tests/QuarantinePolicyAutoEnforcementTests.cs` altında EICAR otomatik karantina ve 60-84 uyarı senaryolarını doğrulayan uçtan uca birim ve entegrasyon test paketi yazıldı.
* **Test Doğrulaması:** Toplam 539 test çalıştırıldı; 0 başarısız, 0 atlanan ile %100 BAŞARILI (PASS).

---

## [3.3.0] - 2026-09-07

### Scan Performance, ETA & Resource Optimization (P2)
* **İmza Kontrolü Fast-Path Önceliği:** `FileHashMatcher.EvaluateHashAndAllowlistAsync` içinde dijital imza doğrulaması SHA-256 hesaplamasından ÖNCE çalışacak şekilde yeniden yapılandırıldı. `System32`, `SysWOW64` ve `Program Files` altındaki geçerli Microsoft, Windows ve Google imzalı sistem dosyaları disk hash'i okunmadan doğrudan temiz-geçiş (bypass) alarak CPU ve disk I/O yükünü sıfırladı.
* **100k FIFO İmza Önbelleği:** `SignatureVerifier` içine `path|size|mtimeUtcTicks` anahtarlı, 100.000 giriş kapasiteli, FIFO tahliyeli eşzamanlı önbellek (`_signatureCache`) entegre edildi. Tekrarlanan sistem dosyası imza denetimleri mikrosaniyelik O(1) bellek içi aramalara dönüştürüldü.
* **Pre-Hash Scan-Cache Denetimi:** `FileHashMatcher` içerisinde dosya hash'i hesaplanmadan önce `_scanCache` kontrolü devreye alındı; aynı tarama döngüsünde veya değişmemiş dosyalarda mükerrer hash hesaplama tamamen ortadan kaldırıldı.
* **Çoklu Paralel Klasör Gezgini (DirectoryWalker Scalability):** `DirectoryWalker.EnumerateDirectorySafelyAsync` BFS kuyruğu, `ConcurrentQueue` ve `ConcurrentDictionary` (dedupe) tabanlı 2–4 paralel gezgin işçisine çıkarıldı (`Math.Clamp(ProcessorCount / 2, 2, 4)`). Yüksek hızlı NVMe/SSD sürücülerde 8192 kapasiteli kanal kuyruğu tam doygunluğa ulaştırıldı; işçi sayısı tavanı (SSD=8 / HDD=2) ve `ThreadPriority.BelowNormal` arka plan önceliği korundu.
* **Gerçek Zamanlı & Tarayıcı Önbellek Paylaşımı:** `RealTimeVerdictProcessor` ile `FileHashMatcher` arasında iki yönlü önbellek paylaşımı sağlandı. Tarayıcının doğrulanmış temiz önbellek kayıtları RT motoruna aktarılırken, gerçek zamanlı korumaya 100 MB üst sınır getirilerek devasa arşiv veya dosya yazımlarında RAM patlamaları engellendi.
* **O(1) Kilitsiz Beyaz Liste (AllowlistService):** `AllowlistService` içerisindeki her dosyada çalışan `_allowlist.Any(...)` doğrusal araması, `ConcurrentDictionary<string, AllowlistEntry>` hash dizini ile O(1) kilitsiz (lock-free) doğrudan sorgulamaya dönüştürüldü.
* **Tarama Tamamlama Gen2 GC Dondurma Çözümü:** `FileScannerService.cs` içindeki çift bloklayıcı `GC.Collect(2, Aggressive, blocking: true)` ve `GC.WaitForPendingFinalizers` çağrıları kaldırıldı; WPF kullanıcı arayüzü geçişlerindeki donma giderildi.
* **Kayan Ortalama ETA ve Gerçek İlerleme Oranı:** `ScanProgress` modeline `ElapsedSeconds` ve `EstimatedRemainingSeconds` eklendi. Son 10 raporun taranan dosya/saniye hızına göre hareketli ortalama kalan süre (`kalanDosya / hız`) hesaplandı; hız 0 olduğunda "tahmin ediliyor" gösterildi. `ProgressPercent`, dosya sayısına göre `(scanned / total * 100)` oranına bağlandı.
* **Süre Formatı Düzeltmesi & Kalan Süre UI Satırı:** `ScanViewModel` içindeki saat devretme hatası (`FormatDuration`) düzeltildi (>= 60 dk durumunda saat/dk/sn gösterimi). `ScanView.xaml` ve `ActiveScanWindow.xaml` içerisine "Kalan: ~4 dk 12 sn (12.340 / 210.547 dosya)" metin satırı eklendi.
* **10.000 Dosyalık Benchmark Kanıtı:** `PerformanceBenchmarkingRunner.Test_10kFilesTree_SignedPassCache_SkipsHashComputation_OnSecondScan` testi ile 10.000 dosyalık dizin ağacında:
  - 1. Tarama: 14.226 ms (10.000 hash çağrısı)
  - 2. Tarama: 1.684 ms (0 hash çağrısı)
  - Hash Atlanma Oranı: %100,00 (Hedef: >= %80)
  - Hızlanma: 8,45x

---

## [3.2.0] - 2026-09-07

### Advanced Threat Prevention & Pre-Execution Gating (P1)
* **ETW Tabanlı Pre-Exec Tarama Katmanı:** `Microsoft-Windows-Kernel-Process` ETW sağlayıcısı (`Microsoft.Diagnostics.Tracing.TraceEvent`) üzerinden süreç başlangıcı (`ProcessStart` / `ImageLoad`) anında tetiklenen yürütme öncesi koruma katmanı (`EtwPreExecProtectionService`) geliştirildi. Şüpheli ikili dosyalar `NtSuspendProcess` P/Invoke çağrısıyla dondurulur; `DetectionHub` ve `RiskScoringEngine` üzerinde maksimum 500 ms içinde analiz edilir. Risk skoru >= 70 ise süreç ağacı sonlandırılır ve dosya karantinaya alınır.
* **Hızlı Beyaz Liste (Fast-Path Whitelisting):** `CriticalProcesses` listesindeki sistem süreçleri, antivirüsün kendi dosyaları, geçerli Microsoft Authenticode/Katalog imzalı ikililer ve L1 önbellek eşleşmeleri 0 ms gecikmeyle yürütmeye bırakılır. Yönetici yetkisi olmayan oturumlarda servis otomatik olarak `FileSystemWatcher` korumasına geri döner (fail-safe).
* **YARA Kural & Desen Motoru (YARA-X Mimarisi):** Rust bellek güvenliği, modern kural desteği ve güvenli FFI mimarisi temelinde `IYaraEngine` ve `YaraEngine` geliştirildi. `C:\ProgramData\UltronDefender\yara\` kural dizini (yazılamazsa `%LOCALAPPDATA%` fallback) yönetilir. Varsayılan olarak abuse.ch standardında 3 kural oluşturulur: `eicar.yar`, `mimikatz.yar`, `cobaltstrike.yar`. `ThreatFeedUpdater` üzerinden 24 saatte bir kural derleme desteği bağlandı.
* **14. Dedektör Eklentisi (YaraDetector):** `DetectionHubFactory` içine `YaraDetector` (`Priority = 12`, `sev = 100`, `EvidenceCategory.StaticSignature`, `Confidence = Absolute`) eklendi. Eşleşen kural adı, bayt ofsetleri ve tanımlayıcılar `SecurityEvidence.Metadata` alanına adli kanıt olarak kaydedilir.
* **Canlı Test Paketi (LiveSampleTests):** `[Trait("Category", "LiveSample")]` kategorisinde test paketi eklendi. abuse.ch MalwareBazaar sorguları katı 30 saniyelik zaman aşımı ile çalıştırılır; indirilen tüm örnekler `%TEMP%` altında işlenip `finally` bloklarında kesin olarak silinir (repoya asla commit edilmez). EICAR testi Hash Lookup + YARA pattern/offset + ETW Pre-Exec gating olmak üzere 3 katmandan birden uçtan uca başarıyla geçirildi.
* **AMSI Sağlayıcı Kaynak Teslimi (`tools/AmsiProvider/`):** `IAmsiProvider` arabirimini ve doğrudan Win32 AMSI fonksiyonlarını (`AmsiInitialize`, `AmsiOpenSession`, `AmsiCloseSession`, `AmsiScanString`, `AmsiScanBuffer`) dışa aktaran unmanaged C++ COM DLL şablonu geliştirildi. Named Pipe (`\\.\pipe\AegisPC_ScanPipe`) üzerinden `DetectionHub`'a bağlanır. COM CLSID (`{638DC8E4-1B1C-4328-8C67-DF52445EFA10}`) ve AMSI sağlayıcı kayıt betiği (`Register-AmsiProvider.ps1`) ile Microsoft Authenticode / ELAM / WHQL imzalama yönergeleri belgelendi (`PARTIAL - imza bekliyor`).
* **Test Paketi Genişlemesi:** Test tabanı 290'dan 309 birim testine (+3 Canlı test ile toplam 312) ulaştı; 0 hata, 0 kilitlenme ile %100 başarı oranı korundu.

---

## [3.1.0] - 2026-09-07

### Security & Integrity Hardening (P0)
* **İmza Veritabanı Temizliği:** `ThreatSignatureDatabase` içindeki doğrulanamayan/sentetik 51 adet hash temizlendi; gömülü veri setinde yalnızca doğrulanmış standart EICAR hash'leri (2 adet) bırakıldı.
* **MalwareBazaar Tehdit Beslemesi & Bootstrap:** `ThreatFeedUpdater` servisi abuse.ch MalwareBazaar JSON API'sine bağlandı. API anahtarı `SettingsService` üzerinden okunup `Auth-Key` HTTP başlığında iletilir, kod içine/repoya gömülmez. 30 saniyelik zaman aşımı (TimeoutSec=30) uygulandı. İlk açılışta `limit=1000` ve kritik tag'ler (`exe`, `rat`, `ransomware`, `stealer` her biri limit=100) ile toplu bootstrap çekilir. 24 saatlik süre dolmadan tekrar sorgulama yapılmayarak nezaket rate-limit kontrolü sağlandı.
* **Linux ve macOS İkili Sınıflandırması:** `elf`, `sh`, `macos`, `macho`, `dylib`, `so` formatındaki örnekler `Category = "Linux/Mac"` olarak etiketlenerek Windows dosya taramalarında izolasyon sağlandı.
* **Veritabanı Bütünlüğü & ACL Korunması:** SQLite imza veritabanına (`threat_signatures.db`) SHA-256 sağlama toplamı doğrulaması eklendi. Harici müdahale (tampering) tespit edildiğinde veritabanı otomatik olarak baştan oluşturulur ve güvenlik günlüğüne kaydedilir. Dosya erişimi Administrators/SYSTEM FullControl, Users ReadOnly olarak sıkılaştırıldı.
* **WSC Kayıt Güvenliği:** `WindowsSecurityRegistrationService` servisine `EnableWscRegistration = false` (varsayılan kapalı) bayrağı eklendi; birincil AV olarak erken konumlanma engellendi.

### Fixed
* **Test Runner Deadlock:** `PerformanceViewModel` ve `AppThemeManager` bileşenlerinde `Application.Current?.Dispatcher?.Invoke` çağrısının, test tamamlanmış STA iş parçacığı üzerinde sonsuz kilitlenmeye (deadlock) yol açması engellendi. Güvenli `DispatchToUi` ve `Thread.IsAlive` kontrolü eklendi.
* **Test Paketi Doğrulaması:** 290 xUnit testi sıfır hata, sıfır uyarı ve sıfır donma ile tamamlandı (%100 PASS).

---

## [3.0.0] - 2026-08-19

### Added
* **Content-Over-Extension Magic Sniffer:** Inspects binary headers (`MZ`, `PK`, `7z`, `Rar!`, `#!`) to detect disguised PE payloads regardless of extension (`.dat`, `.bin`, `.tmp`).
* **Priority Drop Zone Indexing:** Full and Quick scans prioritize user Desktop, Downloads, Temp, and Startup in the first 1–2 seconds.
* **NotificationAggregator:** 3–5 second grouping window that aggregates up to 20 simultaneous routine threats into a single clean summary notification.
* **Single-Instance Mutex & Focus Manager:** Added `Global\UltronDefender_SingleInstance_Mutex` and Inno Setup `InitializeSetup` registry check.
* **Modular DetectionHub Integration:** Connected all 13 detector plugins to Full, Quick, Custom, and Startup scans.
* **Live Host Performance Benchmark:** Measured scan throughput (P50 = 3.82ms, P95 = 28.40ms, P99 = 41.15ms).

### Fixed
* **Full Scan Desktop False Negative:** Fixed root cause where `Directory.EnumerateFiles("C:\\")` aborted on junction points (`System Volume Information`, `$Recycle.Bin`). Replaced with resilient `EnumerateDirectorySafelyAsync` BFS queue.
* **Extension Filter Blind Spot:** Removed hardcoded 16-extension filter that was skipping `.bin`, `.dat`, `.tmp`, `.vbe`, `.hta`, and extensionless binaries.
* **Locked File Crash:** Applied `FileShare.ReadWrite | FileShare.Delete` with retry logic for files actively locked by browsers.
* **Duplicate Re-install Collision:** Inno setup now halts duplicate installation and prompts the user cleanly.

### Security
* Verified 20-threat DPAPI AES-256 atomic quarantine vault isolation.
* Enhanced AMSI script in-memory buffer inspection.
* Zero-mock automated test suite expanded to 202 tests (100% passing).

---

## [2.0.0] - 2026-08-18

### Added
* Deep PE Analyzer with Rich Header XOR decoding, TLS callback detection, and W+X section anomaly checks.
* Multi-layer scan caching (L1 RAM LRU + L2 SQLite Disk DB).
* Process Lineage Tracker and 60-second sliding window Attack Chain Correlator.
* Ransomware mass file burst and Shannon entropy delta guard.
* Safe Archive Engine with zip bomb quotas and recursion depth limits.
