# ⚠️ KNOWN LIMITATIONS & ARCHITECTURAL GAPS

Bu doküman, **Ultron Defender Total Security** platformunun mevcut mimarisindeki tüm teknik sınırları, eksiklikleri ve iyileştirilmesi gereken alanları açık ve net şekilde listelemektedir.

---

## 1. Çekirdek ve Sürücü Sınırları (Kernel & Driver Gaps)

1. **WDK İle Derlenmiş İkili (.sys) Dağıtımı:**
   - `drivers/AegisFilter/` altında C WDK kaynak kodları tamamlanmıştır (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks` ve `AegisFilter.vcxproj`).
   - Geliştirme makinesinde WDK kurulu olmadığı için `.sys` ikilisi derlenmemiş ve test-signing ile yüklenmemiştir. Sürücü ikilisi derlenene ve `fltmc load AegisFilter` yapılana kadar sistem otomatik olarak ETW Pre-Execution + FileSystemWatcher kullanıcı modu korumasına geri döner.
2. **Kullanıcı Modu Kernel IPC Köprüsü:**
   - `AegisPC.Infrastructure/Kernel/KernelIpcService.cs` gerçek `fltlib.dll` (`FilterConnectCommunicationPort`, `FilterGetMessage`, `FilterReplyMessage`, `FilterSendMessage`) Win32 P/Invoke altyapısına kavuşturulmuş, x64 16-bayt hizalama ve 4-worker havuzu eklenmiştir.
   - Sürücü yokken dürüstçe `NotInstalled / Degraded (User-Mode Fallback)` raporlar ve sistemi kilitlemez.
3. **Pre-Operation Koruması Durumu:**
   - Sürücü aktifken kernel düzeyinde `STATUS_ACCESS_DENIED` ve `FLT_PREOP_COMPLETE` döner; sürücü pasifken `EtwPreExecProtectionService` (`NtSuspendProcess`) kullanıcı modu dondurma katmanı devreye girer.

---

## 2. Ağ ve Güvenlik Duvarı Sınırları (Network & WFP Gaps)

1. **WFP Kullanıcı Modu (BFE) ALE Engellemesi Devrede, Kernel Callout Sürücüsü Yoktur:**
   - Ağ koruması, `DnsFilterService` (yerel HOSTS dosya sinkhole + DoH) ve `WfpEnforcementService.cs` (`fwpuclnt.dll` Base Filtering Engine P/Invoke ile `FWPM_LAYER_ALE_AUTH_CONNECT_V4` katmanında dinamik oturumlu IP engelleme) üzerinden yürütülmektedir.
   - Çekirdek düzeyinde derin paket incelemesi (deep packet inspection - DPI) yapan bir WFP Callout sürücüsü yüklü değildir.
2. **TLS/HTTPS İncelemesi Yapılmamaktadır:**
   - Şifreli web trafiği (HTTPS) üzerinde TLS interception uygulanmamaktadır; web koruması alan adı bazlı DNS engellemesi, ALE IP bloklaması ve indirilen dosyaların taranmasıyla sınırlıdır.

---

## 3. Öz-Koruma Sınırları (Self-Protection & Service Gaps)

1. **PPL / ELAM Yoktur:**
   - Microsoft tarafından imzalanmış bir ELAM (Early Launch Anti-Malware) sürücüsü veya PPL (Protected Process Light) sertifikasyonu bulunmamaktadır.
   - Öz-koruma; Win32 API ile Process DACL ve SCM Service DACL (`SetServiceObjectSecurity`) değiştirerek `PROCESS_TERMINATE`, `SERVICE_STOP`, `DELETE` izinlerini kısıtlama seviyesindedir. Sessiz hata yutma kaldırılmış olup hata durumları loglanmaktadır.

---

## 4. Tarayıcı Güvenliği Sınırları (Browser Security Gaps)

1. **Yalnızca Statik Profil ve Eklenti Taraması:**
   - `BrowserSecurityService.cs`, diskteki Chromium (Chrome, Edge, Brave, Opera, Vivaldi) ve Firefox profil dizinlerindeki `manifest.json` ve uzantı dosyalarını statik olarak denetler.
   - Gerçek zamanlı tarayıcı içi DOM manipülasyonu, kimlik avı (phishing) web sayfası engellemesi veya tarayıcı eklenti kancası (in-browser hook) içermemektedir.

---

## 5. Kullanıcı Deneyimi ve Yerelleştirme Sınırları (UX & I18N Gaps)

1. **Merkezi Yerelleştirme (.resx / JSON) Yoktur:**
   - XAML sayfalarında (`DashboardView.xaml`, `ScanView.xaml`, `SettingsView.xaml` vb.) ve ViewModel sınıflarında Türkçe ve İngilizce metinler sabit kodlanmıştır (hardcoded).
   - 12 dil desteği için tekil kaynak yönetim altyapısı kurulmamıştır.
2. **Bildirim Gruplama (Batching) Eksikliği:**
   - Kısa sürede çok sayıda dosya karantinaya alındığında kullanıcıya her dosya için ayrı toast bildirimi gönderilme riski bulunmaktadır; 2–5 saniyelik toplu özet bildirim penceresi tam olarak uygulanmamıştır.
3. **Kritik Tehdit Karşılaşma Ekranı (Critical Threat Overlay):**
   - Yalnızca kritik, aktif ve yüksek güvenilirlikli zararlı aktivitelerde ortaya çıkan yüksek kontrastlı "THREAT CONTAINED" engelleme ekranı henüz bağımsız bir dialog/overlay penceresi olarak eklenmemiştir.

---

## 6. Kod Kalitesi ve Hata Yönetimi Sınırları (Code Quality & Silent Catches)

1. **127 Adet Sessiz Catch Bloğu:**
   - Kaynak kodda **127 adet `catch {}` veya `catch (Exception) {}`** bloğu tespit edilmiştir.
   - Bu bloklar dosya erişim yetersizliklerini, kilitlenmeleri ve beklenmeyen mantık hatalarını gizlemekte, hata ayıklamayı ve adli takibi zorlaştırmaktadır.
