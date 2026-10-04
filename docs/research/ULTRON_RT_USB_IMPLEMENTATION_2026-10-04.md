# Ultron RT, USB/HID ve içerik planı — yerel uygulama kanıtı

Tarih: 4 Ekim 2026. Hedef Defender yanında ek korumadır. Bu rapor bir üretim onayı veya zararlı yakalama oranı değildir. Önceki çalışma ağacındaki değişiklikler korundu; bu çalışma gerçek kullanıcı kasasını, Defender'ı, aygıt politikalarını ve sürücüleri değiştirmedi. Test edilen yayın ayrı `artifacts` dizinine hazırlandı; taşınabilir klasörün farklı ikilisi aşağıda ayrıca kaydedildi.

## Sonuç ve kritik yayın sınırı

Planın karar doğruluğu, servis sağlığı, kasa sahipliği, içerik sınıflandırma ve medya keşfi için kaynak uygulaması bulunmaktadır. Tam plan tamamlanmış değildir. Fiziksel PnP/HID/UASP, kurulu SYSTEM–arayüz ve çok kullanıcı ortamı henüz uçtan uca sınanmadı.

**Önemli işlev sınırı:** Arayüz pipe bağlantısı `Identification` token düzeyinde kalır. Geri yükleme ve kullanıcı isteğiyle manuel karantina, çağıran kullanıcı bağlamında dosya I/O'su yapılamadığı için `CallerContextTokenUnavailable` ile reddedilir. Listeleme/yetkili silme ayrı işlemlerdir; servis kaynaklı otomatik dosya karantinasının motor yolu bu kullanıcı I/O engelinden ayrıdır. Token düzeyini tek başına yükseltmek, sahte servis/pipe üzerinden istemci token'ının çalınması riskini çözmez. Karşılıklı doğrulanmış taşıma ve çok kullanıcı VM testleri tamamlanmadan kasa arayüzü çalışır veya dağıtıma hazır sayılmaz. [Microsoft pipe impersonation](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client), [impersonation düzeyleri](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels).

Standart kullanıcılara başka kullanıcıların yollarını içeren makine-geneli tehdit mesajları gönderilmez. Ancak `OwnerSid` tabanlı kullanıcıya özel RT bildirim yönlendirmesi henüz yoktur; standart hesapta kendi tespitinin bildirimi de eksik kalabilir. Bu da okul/iş dağıtımından önce çözülmelidir.

## Uygulanan yetenekler ve sınırlar

| Alan | Kaynak uygulaması | Doğrulama sınırı |
| --- | --- | --- |
| Karar politikası | Pozitif bağımsız kanıt imza/yol/negatif puanla silinmez. Kesin karar yalnız uygun mutlak statik imza veya başarılı yerel AMSI sağlayıcı kanıtından gelir. Kalıcılık ipuçları review-only. | Gerçek temiz/zararlı korpusu yok; güncellenen imza paketinin üretim kaynak doğrulaması ayrı kapıdır. |
| AMSI | Native HRESULT/sonuç, yönetici politika engeli, fallback ve bilinmiyor ayrılır; metin içerikleri ortak motorla incelenir. Çalıştırma yapılmaz. | Testler inert sağlayıcı kullanır. API bulunması aktif inceleme sayılmaz; son başarılı native istek zamanı ayrıca gösterilir. |
| Koruma sağlığı | 5 saniyelik servis snapshot; 15 saniyede bayat. Gerçek watcher kökleri, kayıp olaylar, kurtarma, ETW ve aygıt keşfi ayrı gösterilir. UI doğrulanmadan yeşil başlamaz. | Sağlıklı seçili gözlem alanı, tüm diskin korunduğu veya erişim öncesi engelleme anlamına gelmez. |
| Fidye gözlemi | Motor servis sahibi; UI yerel watcher/canary başlatmaz. Kanıt taşımayan score/PID API'si yalnız gözlem raporlar; sahte engelleme ve zarara uğrayan dosya sayısı üretilmez. | Saldırgan süreç korelasyonu ve eylem yetkisi henüz yok; bu yol otomatik süreç öldürmez/karantinaya almaz. Kernel CFA değildir. |
| Canary | Yeni dosya oluşturma, exact sahiplik kaydı ve native handle kimliği ile yönetim; aynı adlı kullanıcı belgesi sahiplenilmez. | Sahiplik bellektedir; çökme sonrası kalan eski canary otomatik sahiplenilmez ve aynı yerde yeni oluşturmayı engelleyebilir. Güvenli kalıcı sahiplik makbuzu/temizlik pilotu eksik. Olay saldırgan kanıtı değildir. |
| Kasa | Servis tek sahip; kaynak handle'ından SID; nullable legacy sahipler admin-only. Atomik mükerrer kontrolü, operasyon lease, yedekli schema/ACL geçişi, doğrulanmış streaming restore. | Gerçek eski kasaya göç/rollback uygulanmadı. Arayüz restore/manual containment yukarıdaki taşıma kapısına takılır. |
| İçerik | Uzantıdan bağımsız, sınırlı yapı doğrulaması: PE; ZIP/JAR/OOXML; PDF; PNG/JPEG; metin/betik ve kısayol adayları. Yeniden adlandırılmış arşiv ortak analiz yoluna girer. | Tür tanımak temiz demek değildir. PDF derin içerik çözümleme eksik; şifreli/bozuk/desteklenmeyen/bütçede yarım içerik partial/unknown. |
| USB/disk | PnP register-first; depolama descriptor/bus ve parent ilişkileri; fixed görünen USB/UASP kapsamı; volume GUID + takılma nesli. Watcher önce, mevcut dosyalar sonra. | Fiziksel aygıt ve servis yeniden başlatma pilotu yok. Sürücü harfi aygıt kimliği sayılmaz. |
| HID | Container/instance ve birden fazla işlev ilişkilendirme; yeni klavye/işlev için açıklanabilir gözlem uyarısı. | Firmware güvenliği, ilk kötü tuşu engelleme, keylogging ve otomatik klavye kapatma yok. Beklenen aygıt bildirim tercihi henüz uygulanmadı. |
| Medya kapsamı | Hazır olmayan medyaya 0/1/2/4/8/15 saniye çizelgesi, sonra uzlaştırma; çıkarma iptali; kısmi ilk inventory dahili diski yeni medya sanmaz. Bounded traversal ve ortak arka plan kotası. | Kalıcı checkpoint/resume ve disk başına adil manuel kuyruklar henüz yok. |
| Hızlı/tam/tek dosya | SYSTEM profilleri kayıtlı SID/known-folder ile çözülür. Tek dosya yalnız o dosyayı tarar. Tam tarama hazır yerel Fixed/Removable volume GUID'lerini kullanır. İşlem tamamlanması ile kapsam ayrı raporlanır. | Quick gerçek process/modül okumaları bu güvenli koşuda çalıştırılmadı. Düşük RAM/HDD ve karma disk matrisi eksik. |
| Örtük ağ I/O | Otomatik hedeflerde UNC/device sözdizimi, uzak drive türü ve reparse ataları I/O öncesi sınırlanır; reddedilen kapsam partial. Başlangıç, event, redeploy ve cleanup aynı ilkeye bağlıdır. | Best-effort metadata kontrolü race-free handle-pinned erişim garantisi değildir. Açık özel ağ seçimi ayrı kalır. |

Yukarıdaki tür/drive ayrımı dosyanın temizliğini veya USB firmware güvenliğini kanıtlamaz. `GetDriveType` yalnız drive türünü bildirir; USB kimliği için ayrıca aygıt/depolama ilişkileri gerekir. [Microsoft GetDriveType](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew).

## Hata kökleri ve uygulanmış güvenli davranış

- Eski “MRT/MSRT” adlandırması gerçek MRT çalıştırmıyordu; yerine salt-okunur kalıcılık gözlemi kullanıldı. Ad/yol/komut ipucu kesin malware sayılmaz.
- Hub/plugin başarısızlığı, arşiv kısıtı veya parser eksikliği bulgu olsa bile bağımsız coverage olarak taşınır; kesin bulgu kaybolmaz fakat kapsam tam gösterilmez.
- Exclusion kontrolünün loaded hash doğrulaması DB lazy-init yapıp önceden yüklenen cache'i bozabiliyordu; saf loaded-hash kontrolü ayrıldı.
- Watcher recovery'nin boş kuyruk gözlemi ile sahipliği bırakması arasındaki yarış ve eski neslin yeni taramanın sağlığını bozması düzeltildi.
- Queue/policy/slot hataları dizin erişim hatası sanılıp yutulmaz. Yayınlanmış restore sonrası metadata hatası `AuditPending` olarak ayrılır; başarılı dosya yayınlama yanlış başarısız gösterilmez.
- History JSON hatası mevcut dosyayı sıfırlamaz; eski coverage bulunmayan rapor legacy/unknown kalır. Sahte kısa PDF/JPEG fixture'ları tam temiz dosya sayılmaz.
- Fidye skoruna göre süreç sonlandırma ve dosyayı kilitleyen PID'yi saldırgan sayma kaldırıldı. Canary adıyla kullanıcı dosyasını sahiplenme/cleanup riski giderildi; olay adları gerçekleşmeyen engelleme iddiası üretmez.

## Test kanıtı

Son kaynakla Release çözümü, Review ve Trust derlemeleri **0 uyarı/0 hata** verdi. Son çözüm derlemesi 1,18 saniye sürdü. Sonuçlar TRX çıktılarından okundu:

| Koşu | Sonuç | Yerel kanıt dosyası |
| --- | --- | --- |
| Seçili Review Release | **788 geçti, 1 atlandı, 789 toplam; 0 başarısız** | `implementation-review-complete-final.trx` |
| Trust Release | **35/35 geçti** | `implementation-trust-release-final.trx` |
| Hedefli canary sahipliği | **9/9 geçti**; birleşik Review'a da dahil | `implementation-canary-verified.trx` |
| Benign mikro performans | **5/5 ayrı tekrar geçti**; her tekrarda dört kaynak modu | `implementation-micro-1.trx` … `implementation-micro-5.trx` |

Review filtresi `FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests` idi. Canary test kaynağının paralel düzenlemede Review proje listesinden çıkarıldığı TRX kontrolünde fark edildi; include geri eklendi ve hem hedefli 9 test hem birleşik 789 vaka yeniden çalıştırıldı. Önceki 779 geçiş canary doğrulaması olarak kullanılmaz.

TRX dosyaları yerel `TestResults/Implementation2026-10-04/` altındadır ve Git'e eklenmez. Başlangıçtaki başarısız koşular silinmedi. Review ile Trust arasında 19 ortak vaka vardır; sayılar benzersiz test sayısı olarak toplanmaz.

Atlanan test `LegacyInitializationLockCannotRedirectCreationOutsideVault`: mevcut test token'ında `SeCreateSymbolicLinkPrivilege` yok, native hata 1314. Host politikası değiştirilmedi; bu VM kapısı **geçmiş sayılmadı**. Gerçek NTFS hardlink fikstüründe hedef içerik/ACL değişmeme regresyonu ayrı geçti.

Testler güvenlik karar birimleri, altyapı/sahte PnP–AMSI/IPC–zamanlayıcı senaryoları ve izole benign dosya/NTFS/DPAPI/kasa bileşen regresyonlarıdır. Hepsi malware etkinlik testi değildir. Gerçek kurulu SYSTEM↔UI, fiziksel USB/HID/UASP, signed-driver ve gerçek zararlı/temiz korpus test sayısı bu tur **0**. Fiziksel EICAR oluşturulmadı. Golden01 ve mevcut UI-dispatcher problemli grup dışarıda; ana test DLL'inin tamamı credential/live-kill testleri nedeniyle çalıştırılmadı.

Kullanıcının paralel eklediği Ultron AI dosyaları korundu; bunların dört mevcut duman testi Review sayısına dahildir. Bu tur AI modeli eğitilmedi veya etkinlik açısından denetlenmedi. Mevcut plugin'in heuristik kanıtı tek başına kesin zararlı/otomatik karantina yetkisi değildir; ayrıntılı AI incelemesi sonraki dilimdir.

### Performansın ölçülen sınırı

16 GB RAM/12 mantıksal işlemci/NVMe host'ta 80 × 16 KiB zararsız dosya, beş ayrı test süreciyle tarandı. Dosyalar hemen önce oluşturulduğu için bunlar soğuk disk koşuları değildir. Her mod ayrıca içerik doğrulamalı tekrar tarandı; 80/80 cache hit görüldü. Son kaynak üzerindeki ilk tarama medyanları:

| Mod | Süre medyanı | Süreç CPU zamanı medyanı | Tarama sonunda örneklenen working set aralığı | Son profil işçi sayıları, beş tekrar |
| --- | --- | --- | --- | --- |
| VeryLow | 1055 ms | 938 ms | 91,2–92,5 MiB | 1 / 1 / 1 / 1 / 1 |
| Balanced | 141 ms | 1094 ms | 93,7–120,7 MiB | 1 / 24 / 24 / 24 / 24 |
| Auto | 207 ms | 938 ms | 99,6–126,4 MiB | 1 / 6 / 6 / 6 / 6 |
| Maximum | 191 ms | 1125 ms | 105,4–129,8 MiB | 24 / 24 / 24 / 24 / 24 |

CPU zamanı tüm süreç iş parçacıklarının toplamıdır, CPU yüzdesi değildir; working set tek bitiş örneğidir, **tepe bellek değildir**. Son profil sayısı tarama boyunca etkin işçi ortalaması değildir. Küçük fixture/JIT/host baskısı farklılıkları belirgindir; Maximum bu örnekte Balanced'dan hızlı değildir. Önceki başka kaynak sürümündeki ölçüm geçerli bir önce/sonra karşılaştırması sayılmaz. p95, disk başına MB/s, HDD/karma disk, düşük RAM ve beş soğuk/sıcak temsilî koşu eksik olduğundan ≥%10 hızlanma kapısı **geçilmedi**; kaynak politikasının varsayılanı bu ölçüme dayanarak değiştirilmedi.

### Yayın ikilileri; kurulum yapılmadı

App ve servis `Release --no-restore --self-contained false` ile `artifacts/rt-usb-implementation-2026-10-04/{app,service}` altına yayımlandı; iki komut da başarılı. İkililer bu çalışma tarafından çalıştırılmadı; bu çalışma kurulumu, servis kaydını ve masaüstü kısayolunu güncellemedi. EXE'ler **NotSigned**. Son derlemenin App/Security DLL hash'leri ayrı yayınla eşleşti.

| İkili | SHA-256 |
| --- | --- |
| Ayrı yayın `app/UltronDefender.dll` | `C29B81EAE7B3C2AC5DB3124E39E1F57C66A0B05D234C654D0A729911F5C81736` |
| Ayrı yayın `service/AegisPC.Service.dll` | `0DEBF08BE0D8B8C8FED843F00919B3A2F87A67480D4C5A22590B597317085A10` |
| Ayrı yayın `app/AegisPC.Security.dll` | `FC7D812F0F967FBC5CA036E06745F85DE3F48F042C0D26D26C6B40846A015834` |
| Mevcut taşınabilir `AegisPC_App/UltronDefender.dll` | `5F69BDBB88ED1241DDE950C9B2B2C1B3C46EE8804CA42F09E406E4240930B2CF` |

Son kontrolde taşınabilir App DLL'nin zamanı `2026-10-04 11:54:53 UTC`, ayrı yayının zamanı `11:57:43 UTC` idi. Önceki gözleme göre taşınabilir klasör değişmiştir; hangi paralel işlem değiştirdiği bu raporda doğrulanmadı, üzerine yazılmadı ve bu DLL son kaynak testleriyle doğrulanmış sayılmaz. İki klasörün EXE apphost hash'i aynı olsa da bu **uygulama sürümünün aynı olduğunu göstermez**; gerçek managed DLL farklıdır. Çalışan servis/uygulama envanteri sandbox'ta erişim reddi nedeniyle doğrulanamadı.

## Sonraki uygulama/yayın kapıları

1. Karşılıklı doğrulanmış kullanıcı I/O taşıması + OwnerSid bildirim yönlendirmesi; SYSTEM↔standart/admin çoklu oturum, sahte pipe, kesilme ve yarış VM testleri. Eski kasa ACL/schema/anahtar geçişinde offline yedek/rollback tatbikatı.
2. Ortak değişmez kaynak oturumları, disk başına bounded/adil manuel kuyruk ve RT önceliği; 2–4 GB/HDD, 8 GB/SSD, 16 GB+/karma disk için aynı kapsamla beş soğuk/sıcak tekrar. ≥%10 medyan kazanç, başka yükte ≤%5 kayıp ve artmayan hata kapısı korunur. RAM doldurma veya zorunlu CPU yüzdesi hedeflenmez.
3. Gerçek kullanıcı olay–fidye korelasyonu, üye bazlı mod/JAR raporları, beklenen aygıt yalnız bildirim tercihi; imzalı üretim/USB intel manifesti, replay ve rollback tüketicileri.
4. Desteklenen SDK/runtime'a geçiş, imzalı uygulama/kurulum ve Windows 10/11 sürüm/edisyon pilotu. Bu host'ta SDK 8.0.424 var; .NET 10 geçişi henüz yapılmadı. Microsoft'a göre .NET 8 desteği 10 Kasım 2026'da biter. [Microsoft .NET destek politikası](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core).
5. Minifilter ancak ayrı VM, imzalama, çökme ve geri alma kapılarından sonra; Win7 yalnız API/bağımlılık fizibilitesi. Defender kapatılmaz, Ultron primary AV kaydedilmez, destek dışı işletim sisteminin açıklarını AV kapatıyor denmez.

Yeni kurulum/GitHub yayını bu raporla yapılmış sayılmaz. `codex/av-reliability-stage1` dalında commit/push yapılmadı; HEAD `59591034dd2e098df352dc8a60852521f757b2b4` kaldı. Mevcut kaynak değişiklikleri ayrı incelenebilir dilimlere ayrılmalı; bu rapor eski taslak PR'lara otomatik olarak eklenmedi. Özel `testlog.txt`, `knowledge/`, `memory-bank/` ve `docs/ai` yayın kapsamına alınmaz.

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: kurulu SYSTEM–çok kullanıcı taşıması, eski gerçek kasanın rollback'i, fiziksel USB/UASP/HID olayları, firmware saldırıları, düşük donanımda tepe bellek/verim ve gerçek malware/temiz yazılım başarı oranları henüz ölçülmedi. Tür keşfi, post-operation gözlem ve saldırıyı erişim öncesi engelleme ayrı yeteneklerdir; Ultron Defender'ın yerini alan bir antivirüs olarak sunulmamalıdır.
