# ⚠️ KNOWN LIMITATIONS & ARCHITECTURAL GAPS

Bu doküman, **Ultron Defender Total Security** platformunun mevcut mimarisindeki tüm teknik sınırları, eksiklikleri ve iyileştirilmesi gereken alanları açık ve net şekilde listelemektedir.

---

## 1. Çekirdek ve Sürücü Sınırları (Kernel & Driver Gaps)

1. **Derlenmiş Çekirdek Sürücüsü Yoktur:**
   - `drivers/AegisPC.Driver/` altında C kaynak kodları bulunmaktadır ancak Windows WDK ile derlenmiş geçerli bir `.sys` ikili dosyası mevcut değildir.
   - Sürücü Windows işletim sistemine yüklenmiş ve aktif değildir.
2. **Kullanıcı Modu Kernel Simülasyonu:**
   - `KernelIpcService.cs` ve `KernelGatingEngine.cs` sınıfları gerçek `fltlib.dll` (`FilterConnectCommunicationPort`, `FilterGetMessage`, `FilterReplyMessage`) P/Invoke çağrıları yapmamakta, C# bellek içi simülasyon olarak çalışmaktadır.
3. **Pre-Operation Koruması Eksikliği:**
   - Mevcut Real-Time koruma `FileSystemWatcher` (Post-Operation / dosya oluştuktan sonra) ile çalışmaktadır. Kötü amaçlı bir dosya diskte açılırken veya çalıştırılmaya başlanırken henüz IRP seviyesinde durdurulamaz.

---

## 2. Ağ ve Güvenlik Duvarı Sınırları (Network & WFP Gaps)

1. **WFP Kernel Callout Sürücüsü Yoktur:**
   - Ağ koruması, `DnsProtectionService` (yerel HOSTS dosya sinkhole) ve `NetworkProcessCorrelator.cs` (C# telemetri korelasyonu) üzerinden yürütülmektedir.
   - Çekirdek düzeyinde paket filtreleyen veya port seviyesinde trafiği düşüren bir WFP Callout sürücüsü yüklü değildir.
2. **TLS/HTTPS İncelemesi Yapılmamaktadır:**
   - Şifreli web trafiği (HTTPS) üzerinde TLS interception uygulanmamaktadır; web koruması sadece alan adı bazlı DNS engellemesi ve indirilen dosyaların taranmasıyla sınırlıdır.

---

## 3. Öz-Koruma Sınırları (Self-Protection & Service Gaps)

1. **PPL / ELAM Yoktur:**
   - Microsoft tarafından imzalanmış bir ELAM (Early Launch Anti-Malware) sürücüsü veya PPL (Protected Process Light) sertifikasyonu bulunmamaktadır.
   - Öz-koruma; Win32 API ile Process DACL değiştirerek `PROCESS_TERMINATE` izinlerini kısıtlama seviyesindedir. Yönetici (SYSTEM/Admin) haklarına sahip gelişmiş zararlı yazılımlar veya kernel düzeyindeki tehditler bu süreci sonlandırabilir.

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
