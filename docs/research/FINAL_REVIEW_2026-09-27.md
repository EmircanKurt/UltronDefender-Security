# Son inceleme ve geliştirme kaydı — 2026-09-27

## Sonuç ve kapsam

Bu turda normal tarama, içerik filtreleri, karantina kararı, kullanıcı-modu gerçek zamanlı olay hattı, kaynak yönetimi, AFK zamanlayıcı, IPC ve kurulum scriptleri üzerinde hata düzeltmeleri uygulandı. Son kaynak **Debug ve Release yapılandırmalarında 263/263 seçili regresyonu** geçti. Ayrı güven/güncelleme paketi her iki yapılandırmada **35/35** geçti. Release çözüm derlemesi **0 hata, 0 uyarı**; uygulama ve servis izole klasörlere yayınlandı.

Bunlar ticari antivirüs etkinliği, sıfır yanlış pozitif veya kurulu SYSTEM servisinin uçtan uca çalıştığı anlamına gelmez. Proje hâlâ deneysel önizlemedir. Okul/iş bilgisayarlarına gözetimsiz dağıtım önerilmez. Mevcut Defender/kurumsal koruma kapatılmadı; canlı kurulum, servis kaydı, sürücü, kullanıcı kasası ve ayarları değiştirilmedi. Gerçek zararlı çalıştırılmadı, fiziksel EICAR oluşturulmadı. Önceki “688/713 test”, “commercial-grade”, “Release Ready”, “sıfır yanlış pozitif” etiketleri bu turun kanıtı değildir; README ve güncel özellik matrisi bu nedenle düzeltildi.

## Düzeltilen sorunlar ve nedenleri

| Sorun | Değişiklik | Kanıtın sınırı |
| :--- | :--- | :--- |
| Dosya/klasör adıyla tarama atlama | Medya/metin uzantısı, `Installer` gibi klasörler ve canary benzeri adlar temizliğin kanıtı olmaktan çıkarıldı. Kaynak/repo/Documents dizini geniş beyaz liste değil. | Filtre ve geçici dizin regresyonları; kalan ürün-kökü muafiyeti aşağıda. |
| Fazla yanlış alarm / otomatik müdahale | Genel komut/API metni Absolute zararlı imzası sayılmıyor. Yüksek heuristik puan tek başına otomatik karantina değil; gerçek zamanlı karar Unknown/Warn ayrımını koruyor. | Benign ders/komut metni ve karar tablosu; büyük temiz yazılım korpusu yok. |
| Dosyanın sonundaki desenleri kaçırma | İçerik/API taraması bütün dosyayı iptal edilebilir, örtüşmeli parçalarda okuyor. | 600 KB dosya kuyruğu ve 256 KB parça sınırı; bütün olası formatlar değil. |
| Arşiv uzantısı/üye adıyla kaçış | PK içeriğiyle ZIP/OpenXML tanınır; küçük üyeler uzantıdan bağımsız tamamen incelenir. İç içe kapsayıcı başlıkları, bütçe ve okunamama kısmi kapsamdır. | Renamed ZIP, ZIP içindeki metin ve renamed RAR/7z/gzip/xz başlıkları. |
| Eski temiz cache | İçerik SHA-256 ile doğrulanır; hash listeleri yeniden sorgulanır. YARA reload atomik snapshot yayımlar, süreç içi policy revision değiştirir. Eski revision sırasında başlamış analiz yeni temiz cache yayımlayamaz. | Gerçek benign dosya + kural reload; süreçler arası sürüm protokolü değil. |
| Yanlış dosyanın karantinaya alınması | Otomatik işlemler beklenen SHA-256'ya bağlandı. İşlem sırasında içerik değişmişse kaynak korunur, başarılı işlem/DB kaydı üretilmez. Eksik hash/capability ile müdahale edilmez. Kilit tutan süreçler otomatik öldürülmez. | Geçici dosya, gerçek DPAPI/kasa ve hata geri-alma regresyonları. |
| Çift tarama ve yanlış iptal | Oturum + aktif görev aynı kilitte yayımlanır; eşzamanlı başlatma tek oturumdur. AFK yalnız sahip olduğu taramayı iptal eder; eski oturum yenisini iptal edemez. Politika sırasında iptal Completed olmaz, bulunan bulgular kaybolmaz. | Kontrollü scanner/policy ve gerçek kuyruk testleri. |
| Gerçek zamanlı dar kapsam / olay kaybı | Kuyruklar bounded; medya/metin/uzantısız dosyalar kabul edilir. Overflow/drop görünür, bounded reconciliation vardır; restart eski olayların müdahalesini önler. Normal taramayla kayıtlı DetectionHub/YARA hattı bağlandı. | Kuyruk/karar ve benign FSW testleri; bütün Windows olayları yakalanmış demek değil. |
| ETW ile sahte pre-exec iddiası | Bu katman post-start gözlem olarak ele alınıyor; heuristikle rastgele PID suspend/kill yerine hash-bağlı doğrulanmış dosya kararı kullanılıyor. İnceleme ve worker sayısı bounded, kayıp olay sayılır. | Gerçek ETW/kernel engelleme pilotu yok. Tarihsel API adında `PreExec` kalıyor. |
| Koruma aç/kapat tutarsızlığı | Aynı kayıtlı engine'ler açılıp kapatılır. Required listener hatası rollback; optional ETW hatası FSW/background korumayı geri almaz ama sağlık Partial kalır. Disable bütün listener'ları durdurmayı dener. | Delegate lifecycle testleri; gerçek listener başlangıç/stop başarısı ayrıca pilot ister. |
| Donanımdan bağımsız kaynak seçimi | Gerçek fiziksel RAM ve hedef disk bilgisiyle Auto varsayılanı; disk bilinmiyorsa konservatif, tüm modlarda canlı bellek/CPU basıncı, histerezis ve worker/bütçe sınırı. Dispose bekleyen worker'ı kilitli bırakmaz. | Kontrollü donanım/basınç matrisi ve tek gerçek makinede mikro ölçüm. |
| Session 0 AFK / sahte disk boşluğu | WTS oturum idle; PDH English counter ve iki örnek; bilinmeyen disk/pil/masaüstü durumu erteleme. Tamamlanma zamanları atomik dosyada saklanır, başarısız/iptal edilen koşu intervali ilerletmez. | Zamanlayıcı fake ortam/kalıcılık regresyonları; açık masaüstü AFK kapsamı kısmi. |
| IPC güvenlik/DoS sınırları | 64 KiB frame, 16 bağlantı, bounded istemci kuyrukları/timeouts; explicit ACL, network erişim reddi, OS admin/SYSTEM yetkisi, özel tehdit yollarına kısıtlama. UI servis PID'sini SCM ile doğrular. Eksik/duplicate komut ve hatalı HMAC/nonce tarihleri reddedilir. | Parser/ACL/pipe kimlik testleri; gerçek çoklu kullanıcı/SYSTEM pilotu yok. |
| Kurulum kırıkları | Servis adı ve executable-path quoting düzeltildi; başarısız publish dağıtıma devam etmiyor. Kernel kurulumu varsayılan zorunlu işlem değil. | Üç PowerShell scripti AST parse: 0 syntax error; installer çalıştırılmadı. |

Önemli kaynak karşılıkları (satırlar bu inceleme anındaki kaynak içindir):

- DOĞRULANDI `[src/AegisPC.Security/Scanning/FileScannerService.cs:138]`: analiz başında revision yakalanıyor; cache publish çağrıları bu revision'ı kullanıyor. `[FileScannerService.cs:234]`: desteklenmeyen kapsayıcı başlığı da kapsam hatası; salt uzantı kontrolü değil.
- DOĞRULANDI `[src/AegisPC.Security/Safety/TransactionalQuarantineEngine.cs:298]`: beklenen SHA-256 kaynak snapshot'ı ile karşılaştırılıyor. `[src/AegisPC.Security/Scanning/QuarantineService.cs:108]`: ForceKillHoldingProcesses=false.
- DOĞRULANDI `[src/AegisPC.Security/Scanning/ScanCoordinatorService.cs:448]`: politika sonrası iptal kontrolü var. `[src/AegisPC.Service/IPC/ProtectionCommandLifecycle.cs:28]`: health ile required activation ayrı değerlendiriliyor.
- DOĞRULANDI `[src/AegisPC.Security/Scanning/AdaptiveScanResourceManager.cs:118]`: hedef disk sorgusu; fiziksel RAM sorgusu `[AdaptiveScanResourceManager.cs:149]`. `[src/AegisPC.Core/Models/ScanResourceProfile.cs:165]`: available RAM cap, worker başına 64 MiB headroom.
- İDDİA EDİLDİ AMA BU TURDA KARŞILIĞI DOĞRULANMADI: “gerçek pre-exec engelleme”, “sıfır false positive”, “tüm PC'lerde hızlı”, “kurulu sistemde bütün koruma modülleri ACTIVE”. Birim testler bunları kanıtlamaz.

## Araştırmanın tasarıma etkisi

Araştırma birincil Microsoft/.NET/Win32 belgelerine dayandı; başka bir antivirüsün özellikleri bu projeye otomatik aktarılmış sayılmadı.

1. Tarama hızı yalnız CPU miktarına değil, içerik karmaşıklığı ve I/O'ya bağlıdır. Uzantılar aldatılabilir; Temp'i geniş muaf tutmak risklidir. Sürekli full scan yerine hızlı tarama + gerçek zamanlı koruma yaklaşımı esas alınabilir. Burada çıkarımımız: işçiyi ölçerek artırmak, güveni dosya adına bağlamamak ve bilinmeyen kapsamı göstermek gerekir. [Microsoft scan best practices](https://learn.microsoft.com/en-us/defender-endpoint/mdav-scan-best-practices).
2. FileSystemWatcher buffer taşabilir; buffer büyütmek non-paged belleğe maliyetlidir. Bu yüzden sınırsız kuyruk/“sıfır olay kaybı” iddiası yerine drop/overflow telemetrisi, bounded worker ve yeniden uzlaştırma kullanıldı. [FileSystemWatcher.InternalBufferSize](https://learn.microsoft.com/en-us/dotnet/api/system.io.filesystemwatcher.internalbuffersize).
3. ETW bir olay izleme hattıdır ve tüketici yavaşsa olay kaybı olabilir. Bizim post-start consumer'ımızın bir süreç başlamadan engellediği sonucu bu mekanizmadan çıkarılamaz. [About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing).
4. GetLastInputInfo yalnız çağıran oturumun bilgisini verir; SYSTEM Session 0 sonucunu kullanıcının AFK durumu saymak yanlıştı. WTS oturum yaklaşımı kullanıldı, belirsiz durum erteleniyor. [GetLastInputInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getlastinputinfo), [WTSQuerySessionInformationW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw).
5. English PDH API dil-bağımsız sayaç ekler; Türkçe Windows'ta lokalize ad varsayılmıyor. Başarısız ilk örnek “disk boş” değildir. [PdhAddEnglishCounterW](https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhaddenglishcounterw), [Collecting Performance Data](https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data).
6. Named pipe için yalnız ad veya varsayılan ACL yeterli güven sınırı değildir. Explicit erişim ve istemci yetkisi; UI tarafında gerçek SCM PID kimliği birlikte ele alındı. [Named Pipe Security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [GetNamedPipeServerProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid), [QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex).
7. GC zorlamak genel hızlandırma çözümü değildir; .NET'in normal toplama politikası ve ölçüm esas alınmalıdır. Bu turda hız elde etmek için sürekli GC/priority yükseltme eklenmedi. [Induced collections](https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/induced), [GC performance](https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/performance).

## Ölçülen performans — sonucu doğru yorumlamak

Kaynak: `TestResults/FinalReview/review-release-final.trx`, `ResourceModes_CompleteBenignFiles_WithMeasuredCpuMemoryAndCache`.

Makine: Windows 11 Pro 10.0.26200, 12 mantıksal CPU, yaklaşık 15,9 GiB fiziksel RAM. Her moda ayrı dizinde 80 × 16 KiB benign dosya; gerçek FileScannerService/dedektör hattı; ardından aynı dosyalara cache taraması. OS disk cache soğutulmadı. Ölçüm bir test-host sürecinde ve tek geçişte yapıldı; üretim servisi, başlangıç kurulum analizi veya düşük donanım sertifikası değildir.

| Mod | İlk tarama ms | Dosya/sn | Process CPU ms | Sondaki RSS MiB | Tahsis MiB | Gen2 | Başlangıç worker | Advisory bütçe MiB | Tekrar ms / cache hit |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| VeryLow | 1685 | 47,5 | 1875 | 147,1 | 43,0 | 1 | 1 | 128 | 57 / 80 |
| Balanced | 222 | 359,6 | 1828 | 149,6 | 45,3 | 2 | 24 | 2048 | 5 / 80 |
| Auto | 350 | 228,8 | 2031 | 160,9 | 37,2 | 0 | 24 | 2048 | 5 / 80 |
| Maximum | 271 | 294,7 | 1875 | 168,9 | 39,0 | 1 | 43 | 2803 | 5 / 80 |

Her modda 80 dosya tamamlandı, failure=0. Cache isabeti SHA-256 tekrar doğrulamasını içeriyor; “disk okumadan güven” değildir. CPU ms bütün test-host'a aittir, yalnız scanner'a atfedilemez. RSS sondaki süreç belleği, **peak bellek değildir**. Advisory bütçe hard process memory limit değildir: örneğin VeryLow 128 MiB iken test-host RSS 147,1 MiB'dir. Auto başlangıç profili mevcut basınca göre değişebilir; farklı Debug koşusunda 6 worker/512 MiB gözlendi.

Bu ölçümde Maximum, Balanced'dan yavaş. Bu nedenle “daha fazla sistem kullanımı = daima daha hızlı tarama” doğru bir optimizasyon hedefi değil. Ölçülen fayda: seçilen pacing/worker politikası gerçekten farklı throughput üretiyor ve içerik doğrulamalı cache tekrar işini azaltıyor. Değişiklik öncesi eşdeğer benchmark yok; yüzde hızlanma iddia edilmiyor. 80 küçük dosya sonucu GB'lık arşiv, HDD/USB, Office, oyun kurulumları veya ağ sürücülerine genellenemez.

Varsayılan öneri: **Auto**. HDD veya ciddi RAM basıncında konservatif davranış; kullanıcı iş yaparken Balanced/Low seçimi; Maximum ancak ölçülen fayda varsa. Şu an throughput'u kapalı döngüde optimize eden öğrenilmiş bir algoritma yok; basınç ve donanım temelli politika var.

## Test kayıtları ve başarısızlığın dürüst kaydı

Ana `AegisPC.Tests.dll`, bu koşumda Defender tarafından `HackTool:Win64/PSWDump.MX!MTB` olarak işaretlendi. Defender Operational 1116/1117 olayları okundu; bu sınıflandırma tek başına uygulamanın zararlı olduğu kanıtı değildir. Ana projede canlı kimlik bilgisi/süreç müdahalesi testleri de bulunuyor. `final-regression.trx` **total=0** içeriyor: başarılı test kanıtı olarak sayılmadı. Defender kapatılmadı, dosya restore edilmedi veya exclusion eklenmedi.

Mevcut repo `AegisPC.Trust.Tests` yaklaşımına benzer şekilde yalnız incelenmiş benign kaynakları açıkça derleyen `AegisPC.Review.Tests` eklendi. Yeni üretim bağımlılığı yok. Golden01 fiziksel EICAR ve iki UI/STA test grubu filtreyle çalıştırılmadı. Ana paketin bütün testlerini geçirdiğimiz iddia edilmez.

| Kanıt | Sonuç |
| :--- | :--- |
| `policy-nested-before.trx` | 3/3 RED: YARA eski clean cache ×2, renamed nested ZIP complete. |
| `policy-cancel-before.trx` | 1/1 RED: politika sırasında iptal Completed döndü. |
| `optional-telemetry-before.trx` | 3/3 RED: optional listener sağlık/rollback hataları. |
| `container-header-red.trx` | 4/4 RED: renamed RAR/7z/gzip/xz yanlış Success. İlk zayıf fixture null dependency yüzünden yanlış pozitif “geçti”; bağımlılık ve hata sebebi assertion'ı düzeltildikten sonra gerçek RED alındı. |
| `safe-regression.trx` | Ara sürüm 256 geçti / 3 eski beklenti başarısız. Bu dosya final değildir. |
| `review-final.trx` | Son Debug kaynak: 263 geçti / 0 başarısız / 0 atlandı. |
| `review-release-final.trx` | Son Release kaynak: 263 geçti / 0 başarısız / 0 atlandı. |
| `review-explicit-source-final.trx` | Wildcard yerine açık kaynak listesine geçiş sonrası aynı 263 Release regresyonu geçti. Performans tablosu önceki `review-release-final` örneğidir. |
| `trust-final.trx`, `trust-release-final.trx` | Ayrı paket: her yapılandırmada 35 geçti. Review ile 19 PhaseTwo vakası ortaktır; toplamlar benzersiz test sayısı gibi toplanmaz. |
| `dotnet build AegisPC.sln -c Release --no-restore` | 0 hata / 0 uyarı. |
| App ve Service `dotnet publish -c Release --no-restore` | İki izole yayınlama tamamlandı; dosyalar çalıştırılmadı. |
| PowerShell AST kontrolü | install.ps1, scripts/install.ps1, build_and_deploy.ps1: her biri 0 syntax error. |

263 vakanın ihtiyatlı kaynak inceleme sınıflandırması: **45 benign güvenlik bileşeni entegrasyonu**, **104 güvenlik birim/bileşen regresyonu**, **114 altyapı/yaşam döngüsü/performans**. Birleşimli theory vakaları ayrı sayılır. Entegrasyon için gerçek disk/OS kaynağı + gerçek karar sınıfı + somut güvenlik kararı birlikte aranmıştır; gerçek FSW'nin stub verdict üretmesi tek başına AV entegrasyonu değildir. Bu sayı malware yakalama oranı değildir.

Golden02/03/04/05 çalıştı. Golden01 çalıştırılmadı; dolayısıyla “Golden tam 5/5 ve fiziksel EICAR pipeline doğrulandı” denemez. ZIP/başlık ve ders notu fikstürleri benign; karantina testleri yalnız kendilerinin oluşturduğu geçici kasayı kullanır. Yayınlanmış exe/servis başlatma, SYSTEM DPAPI↔UI erişim ve Inno Setup kurulum testi yapılmadı.

Tekrarlamak için (normal Windows kullanıcı profili gerekir; DPAPI kısıtlı sandbox'ta başarısız olabilir):

```powershell
dotnet test tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --filter "FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests&FullyQualifiedName!~ScanViewModel_CancelCommand"
dotnet test tests/AegisPC.Trust.Tests/AegisPC.Trust.Tests.csproj -c Release
dotnet build AegisPC.sln -c Release
```

TRX dosyaları gitignore kapsamındaki yerel kanıttır; bu MD ana sonuçları kalıcı kaydeder. Kontrolsüz biçimde `dotnet test AegisPC.sln` ile canlı testleri başlatmayın.

Çalışma ağacı önceden çok sayıda değişiklik içeriyordu; bunlar korunmuştur. Global `git diff --check` bazı mevcut/ilgisiz satırlarda whitespace bildirdi; toplu format veya reset yapılmadı. Son cache/coordinator/scanner ve güncellenmiş legacy test dosyalarının hedefli diff kontrolü whitespace hatası vermedi. Yeni Review projesi wildcard yerine açık kaynak listesi kullanır; ileride eklenen canlı testleri kendiliğinden derlemez.

## Yayınlanan çıktılar

- `artifacts/final-review-2026-09-27/app/`
- `artifacts/final-review-2026-09-27/service/`

Bunlar framework-dependent .NET 8 Release dosyalarıdır; kurulum paketi ve imzalı antivirüs yayını değildir. Çalıştırmak için uygun .NET 8 Desktop/NET runtime gerekir. Hash yalnız dosya kimliğidir, yayıncı güveni/imzalama kanıtı değildir.

| DLL | SHA-256 |
| :--- | :--- |
| UltronDefender.dll | `7BDB42E1638809633AF55B577D71E8004E6A6BFC4E4EF33D15CE543937BF114D` |
| AegisPC.Service.dll | `27B9D269DED97525849C5E32DBF1BB677275B36724FECDEE91F1EFD5C8908569` |

## Kalan kritik işler — dağıtım öncesi plan

### P0 — tek güvenlik sahibi ve güven sınırları

1. **Servis kasanın tek sahibi olmalı.** UI bugün kendi quarantine/motor singleton'larını da oluşturuyor (`src/AegisPC.App/Startup/ServiceRegistration.cs:97`). Karantina ACL helper'ı current user'a FullControl ekliyor (`TransactionalQuarantineEngine.cs:100`). SYSTEM + farklı kullanıcıların aynı kasa/anahtar/DB üzerinde bağımsız sahipliği; DPAPI, reparse ve standart kullanıcı müdahalesi riskidir. Bu tur legacy kasa migrasyonu yapılmadı. Mimari değişiklik öncesinde mevcut kasaların yedeği, sahiplik seçimi ve geri dönüş tasarımı gerekiyor.
2. **UI yalnız kimliği doğrulanmış servis istemcisi olmalı.** Scan/quarantine/restore komutları kullanıcı/oturum yetkisiyle taşınmalı; standart kullanıcı diğer kullanıcıya ait dosya yollarını görememeli. Şimdiki admin-only mutation yaklaşımı güvenli kısıtlamadır, normal okul kullanıcısı için tam kullanılabilir deneyim değildir.
3. **Self-owned path muafiyeti daraltılmalı.** Repo ve sahte klasör bypass kaldırıldı, fakat gerçek runtime/state kökü halen muaf. Yazılabilir portable binary/state dizini saldırgan için muafiyet olabilir. DACL/owner, canonical handle ve ürün dosya kimliğiyle dar kapsam gerekir; salt ürün klasörü adına güven dağıtım garantisi değildir.
4. **Üretim imzalama ve güncelleme protokolü.** Authenticode, production manifest key, kalıcı anti-replay/rollback ve servis sahibinde atomik güncelleme pilotu tamamlanmalı. Anahtar eksikse güncelleme fail-closed kalmalı. Defender/WSC devre dışı bırakılarak bu açıklar örtülmemeli.

Kabul testi: izole VM'de SYSTEM servis + admin UI + iki standart kullanıcı; mevcut kasayı kaybetmeden migration; yetkisiz restore/settings reddi; sahte pipe/symlink/DB/key saldırısı; servis stop/restart ve kesintide sağlam geri dönüş. Native sürücü olmadan bunu “pre-exec” diye adlandırmamak gerekir.

### P1 — kullanıcı oturumu ve düşük donanım

5. **Açık masaüstünde gerçek AFK:** güvenilir kullanıcı-oturumu ajanından SID/session-bound, tazelik kontrolü olan idle/fullscreen bilgisi. Şu an servis kilitsiz açık oturumun fullscreen durumunu bilemediğinde taramayı erteler; “bilgisayarı bırakınca her durumda AFK tarar” özelliği henüz tam değil. Pil, RDP/multi-session ve user-return testleri eklenmeli.
6. **Bütün modüllerin bellek bütçesi:** scanner bütçesi advisory; process RSS/peak, LOH, ETW buffer ve dedektör başına in-flight maliyet ayrı izlenmeli. Eski `EtwProcessMonitor` hâlâ sabit 256 MB buffer ve sabit session name kullanıyor; bu tur değiştirilmedi. Scanner mikro ölçümü üretim servisinin toplam düşük-RAM maliyetini kanıtlamaz.
7. **Ölçüme dayalı throughput ayarı:** aynı koruma kapsamını sabit tutup worker 1/2/4/8/16... taraması, throughput p50/p95, CPU-time/file, disk queue ve UI latency. Daha fazla worker hız vermiyorsa azalt; 3 örnek histerezisi koru. Sadece düşük CPU gördük diye öncelik yükseltme veya daha çok thread üretme yok.

Cihaz matrisi: 2/4 GB RAM + HDD, 8 GB + SATA SSD, 16/32 GB + NVMe; AC/pil, USB, OneDrive yönlendirilmiş profil, RDP, kilitli/açık masaüstü, yüksek mevcut RAM basıncı. Her cihazda küçük dosya, büyük PE, Office/ZIP, bozuk/nested/encrypted arşiv ve kilitli dosya korpusu; en az 5 tekrar, soğuk/sıcak cache ayrımı, peak RSS ve p95 UI gecikmesi. Veri toplamadan “tüm PC'lerde iyi” sonucu yok.

### P2 — gerçek antivirüs etkinliği ve kapsam

8. Yönetilen YARA alt kümesi yaklaşık 16 MB kapsam limitine sahip; büyük dosyalar ve desteklenmeyen kurallar partial/Unknown kalmalı. ZIP'in sınırlı üyeleri inceleniyor; nested recursive tarama, RAR/7z/ISO/tar/şifreli arşivler için sandbox/bütçeli parser gerektiği açıkça raporlanmalı. Magic-header kontrolü bütün formatları kapsamaz.
9. İmzalı minifilter/AMSI provider gerekiyorsa ayrı onaylı Windows VM pilotu: WDK, imzalama, Secure Boot/HVCI, fail-open deadline, driver crash/stress ve kaldırma. Bu tur testsigning açılmadı, sürücü yüklenmedi. AMSI consumer kullanmak sistem çapında provider kaydı anlamına gelmez.
10. Temiz okul/iş yazılımı korpusunda false-positive ölçümü; dosya adı whitelist yerine doğrulanmış yayıncı/hash/evidence. Sonra yalnız yetkili izole laboratuvarda tespit korpusu ve standart benign EICAR/AMTSO kontrolleri. Araç/API sözcüğü içeren program otomatik malware sayılmamalı; bağımsız davranış/kanıt gerekir. Üretim yakalama yüzdesi şu an bilinmiyor.

## Şüphecilik ve Doğrulama Notu

Şu an tam doğrulayamadığım başlıca noktalar: kurulu SYSTEM servisinden gerçek ETW→scan→content-bound quarantine→UI uçtan uca hattı, farklı kullanıcıların aynı kasayla güvenli çalışması, açık masaüstü AFK, düşük RAM/HDD üzerindeki peak bellek ve UI gecikmesi, installer/sürücü imzalama ve gerçek malware etkinliği. Testleri geçen kod, bu eksikleri gidermiş sayılmaz. Bu turdaki sınırlı düzeltmeler ve güvenli yayınlama doğrulandı; geniş kurumsal dağıtım veya Defender'ın yerine geçme onayı verilmedi.
