# Ultron AI güvenlik şefi — ilk uygulama dilimi, 2026-10-04

Bu rapor **P0 karar/arıza düzeltmelerini, testli karar/izin çekirdeğini ve robot arayüzünü** kapsar. Planın tamamı bitmedi. Bağımsız Guardian'ın üretim koruması, servisler arası kasa devri, tüm güvenlik işlemlerinin merkezileştirilmesi ve otomatik acil müdahale **henüz etkin değildir**. Kurulu ürün ve Defender değiştirilmedi.

## Uygulanan ve yerel olarak doğrulanan değişiklikler

- `BehaviorEngine` artık olay türü, encoded komut, ad/yol veya yinelenen puanla süreç ağacı öldürmez, dosya karantinaya almaz, `Contained` bildirimi üretmez. Kayıtlar `ObservationOnly`; eylem `None`. Oluşum zamanı olmayan aktör `Unknown`; bildirilen oluşum zamanı da bağımsız doğrulama sayılmaz. Olay/kayıt/geçmiş sınırlı, tekrarlar tekilleştirilmiş, abone ve audit hataları izole edilmiştir. Eski PID-only correlator erişim uyumluluğu için durur ama bu karar yolunda kullanılmaz; onun testleri zararlı etkinliği kanıtı değildir.
- Eski Ultron AI statik puanı artık zararlı olasılığı değildir (`MalwareProbability=null`). Yüksek entropi, paketleyici bölümü ve API importları inceleme önceliğidir; kesin zararlı, sıfır-gün, MITRE yürütümü veya otomatik engelleme iddiası üretmez. İmza/yol puanı azaltmaz. Bozuk/eksik/okunamayan veri `Unknown/Partial` olur.
- AI yolu uzantı veya geliştirici/sistem diziniyle atlanmaz. Manuel ve RT hub değerlendirmesinde caller-owned locked stream paylaşılır; özellik okuması konumu geri koyar, stream'i kapatmaz. PE metadata bütçesi 4 MiB, genel entropi örneği 1 MiB, bölüm örneği 256 KiB. Daha büyük PE tam özellik incelemesi sayılmaz. Bu modülün aynı PE/entropi/import özellikleri ikinci kez DetectionHub puanı üretmez; ayrı inceleme sonucu bağlamda tutulur. Diğer dedektörlerin ortak-feature deduplikasyonu bu dilimde bütünüyle yeniden yazılmadı.
- Tarama `throw/Failed/null/nonterminal/foreign cancellation/channel error` yolları tek terminal sonuç üretir. `ScanFailureInfo` aşama, neden, güvenli açıklama, yerel kod ve korelasyon taşır; rapor ve UI aynı sonucu kullanır. Scanner invocation-local kısmi bulgular/kapsam/sayaçlar korunur, RT genel bulguları taramaya mal edilmez. İptalle eşzamanlı bağımsız fault `Failed` kalır. Abone hataları başarılı taramayı değiştirmez; rapor yazma hatası ayrıca gösterilir.
- Servis açılışı ve sonradan fidye kalkanı etkinleştirme `RansomwareShieldActivation` üzerinden aynı profil/kullanıcı-documents çözümleyicisini kullanır. Start/stop seri; sıfır etkin kök başarı sayılmaz. Kök çözümleme eksikliği watcher kaybından ayrı sağlık boşluğu olarak tutulur. ACL/çok kullanıcı doğrulaması hâlâ VM kapısıdır.
- App DB şeması ve ayarlar dependent view model/aboneliklerden önce beklenir; schema işlemleri transaction içindedir. Geçici SQLite fixture'ında eksik `AuditLogs` yeniden oluşturulması/idempotency ve başarısız schema rollback sınandı. Başlatma hatası splash'i açık bırakıp modülleri başlatmaz. Bu, geçmiş `AuditLogs` hatasının bugünkü kullanıcı runtime hatasının kesin nedeni olduğunu kanıtlamaz; standart kullanıcı machine-DB yetkisi gerçek pilotta sınanmalı.
- “Çözüldü” düğmesiyle gizli allowlist ekleme, finding resolve ve karantina silme kaldırıldı. “İncelendi” yalnız inceleme onayıdır. Eski kalıcı path-dismiss tercihi yeni finding/karantina kaydını gizlemez. Gözlem aynı ID ile güncellenebilir; path eşleşmesi INC gözlemini karantinaya alınmış saldırgan olarak yeniden etiketlemez.

## Merkezi çekirdek — testli, native entegrasyonu kapalı

`IUltronDecisionEngine`, `IProtectionActionBroker`, `IGuardianHealthMonitor`, `ActionPermit/ActionReceipt` ve dosya/süreç kimliği sözleşmeleri eklendi.

- Karar: origin-event/feature tekilleştirme, aile başına tavan ve 512 kanıt bütçesi. Puan yalnız inceleme önceliği; UI'dan “confirmed” alanı gelmesi native yetki değildir.
- Broker: bağımsız validator zorunlu; caller/file/hash/kanıt-revizyonu/politika bağlı 15 sn tek kullanımlık permit, 256 bekleyen limit. Yanlış SID, sahte/değişmiş permit, süre sonu, değişen hash/revizyon, PID oluşum değişikliği ve kritik nesne reddedilir. Gerçek adapter henüz yok: `PilotGatedActionAdapter` bütün native önerileri reddeder. Termination, startup disable ve restore bu çekirdekte de henüz permit alamaz.
- Kalıcı atomik native file-handle doğrulaması ve execute-time yarış garantisi yalnız bu record/fixture testlerinden çıkmaz. Bu yüzden yeni broker **mevcut Ultron işlemlerinin tamamının üretim sahibi değildir**. Mevcut servis kasanın sahibi kalır; iki servis yazıcısı başlatılmadı.
- Hash/aile/kullanıcı bağlı 24 saatlik davranış-bildirim tercihi ve 128 örnek EWMA/median/MAD yardımcıları testlidir, canlı bildirim/telemetri hattına henüz bağlanmadı. Preference kesin içerik kanıtını bastıramaz; missing/nonfinite ölçüm sıfırmış gibi üretilmez.
- Sağlık çekirdeği 5 sn heartbeat/üç eksik gözlem; heartbeat tek başına watcher/kasa sağlığı değildir. Kurtarma yalnız öneridir; 5/15/60 sn cooldown, 10 dk içinde en fazla üç rezervasyon, bakımda restart yok. SCM restart/native eylem yapılmaz; heartbeat kaybına saldırı denmez.

## Guardian ve arayüz

`src/AegisPC.Guardian` ayrı `UltronGuardian.exe` üreten, Windows-service hosting altyapılı **source-only pilot** projedir; solution derlemesine eklendi, installer dağıtımına alınmadı. Varsayılan başlatmanın aktivasyonu reddedip exit2 döndürmesi ayrıca doğrulandı. Açık pilot seçeneği kritik gözlemci ve kasa sahipliğini `unverified/degraded` bırakır; bu opt-in host/SCM akışı çalıştırılmadı ve native action adapter kapalıdır. Henüz bağımsız fidye/RT koruması olarak kullanılmamalıdır.

Robot ortak XAML vektör bileşenidir: mevcut cloud/prompt silueti, 78×70 DIP görsel, daha geniş 100×92 erişilebilir düğme alanı, koyuda mavi/açıkta `#EF4444`. Göz/prompt pencere içi ±2,5 DIP; 34 ms tick, hedefe ulaşınca timer durur. Gizli/minimized/inactive/unloaded durumda pointer tracking/timer durur; global hook/tuş kaydı yok. Windows azaltılmış hareket veya düşük render tier hareketi kapatır. Sayfa girişinin çakışan animasyonları tek fade sahibine indirildi.

Robot klavyeyle de **Ultron AI Koruma Merkezi** sayfasını açar. Sayfa gerçek servis sağlık snapshot'ını sorgu zamanı ve kapsam boşluklarıyla, yerel olay sayısını makine-geneli olaylardan ayrı gösterir. Guardian/otomatik müdahale/geri alma hattının bekleyen doğrulaması açıktır; sohbet veya hazır olmayan işlem düğmesi yok. Bu merkez henüz kanıt/permit/receipt geçmişinin tamamını servis üzerinden sunmaz.

## Son test kanıtı

- Solution, Guardian (ayrı proje), Review ve Trust Release build: **0 hata / 0 uyarı**.
- Son seçili Review: **880 geçti / 1 atlandı / 0 başarısız (881 toplam)**, `TestResults/UltronChief2026-10-04/chief-delivery-verified.trx`.
- Son Trust: **35/35**, `chief-delivery-trust.trx`. Review ile ortak vakalar bulunduğu için sonuçlar ayrı benzersiz güvenlik vakası olarak toplanmaz.
- Ek son kontroller: gerçek çalıştırılmayan PE metadata fixture'ı/renamed PE/bütçe/nonfinite vektör dahil AI 13/13; aynı-yol gözlemin kesin finding'i gizlememesi dahil startup/UI 6/6. Finding ve karantina kayıtları yalnız dosya yoluyla birleştirilmez, finding ID tam GUID kullanır; tekilleştirme HashSet ile yapılır. Bunlar Review toplamına dahildir.
- Hedefli yeni çekirdek/AI/scan/behavior/UI seçimi 80/80; robot outline/theme/lifecycle ayrı 27/27, bu vakalar Review toplamına dahildir.
- Robot offscreen WPF render: dark/light 96 DPI, dark 144 DPI, light 192 DPI; iki tema PNG'si ayrıca görsel incelendi. Canlı masaüstü/minimize/mouse hareketi ve tam uygulama gezinmesi çalıştırılmadı.
- Atlanan fixture: `LegacyInitializationLockCannotRedirectCreationOutsideVault`; test token'ında symlink yetkisi yok. Host politikası değiştirilmedi, başarı sayılmadı.
- Whole main test DLL çalıştırılmadı: canlı kill/credential/EICAR senaryoları bu kaynak doğrulamasının kapsamı değil. Kurulu servis, gerçek vault, gerçek zararlı, fiziksel USB/HID, kullanıcı oturumları değiştirilmedi.
- p95 karar ≤50 ms/eylem başlangıcı ≤1 sn, 2–4 GB/HDD/SSD/NVMe matrisi ve beş soğuk/sıcak tekrar **ölçülmedi**. Bu sayılar hedef; başarı iddiası değildir.
- Bu tur commit/push/installer/portable uygulama üzerine yazma yapılmadı; eski kurulu ürün bu kaynak değişikliklerini otomatik kullanmaz.

## Devam sırası / açık kapılar

1. Karşılıklı doğrulanmış Guardian↔UI ve scan-service IPC; gerçek caller-context I/O, OwnerSid bildirim yönlendirmesi. Mevcut UI restore/manual quarantine hâlâ fail-closed.
2. Tek ömürlük vault-owner lease, eski writer durması, yedek/doğrulanmış migration/rollback; iki kullanıcı SYSTEM VM. Sonra Guardian'a kritik observer devri ve gerçek heartbeat bağlantısı.
3. Dosya I/O–thread–process/boot/başlangıç korelasyonu; yanlış-pozitif VM kapısından sonra actor-bound sınırlı termination. Dosyayı tutan süreç saldırgan sayılmaz.
4. Startup tüm kullanıcılar/Run/logon/lnk, kalıcı before-state/restore; görev odaklı tanılama kartları ve Windows onaylı kurtarma akışı. Boot değişikliği veya otomatik reboot yok.
5. Tüm Ultron mutation girişlerini broker'a taşıma; kullanıcı onayı/24h tercihi/receipt/undo UI. Ölçüm ve imzalı yayın; güncel desteklenen .NET'e kontrollü geçiş.

Microsoft protected antimalware servisleri ELAM/imzalama gerektirir; bağımsız user-mode EXE bunu sağlamaz. [Microsoft protected service gereksinimleri](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-). Dosya I/O olayları thread/file ilişkisinin kaynağıdır; klasör bildirimi tek başına yazan süreci kanıtlamaz. [Microsoft ETW FileIo_ReadWrite](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-readwrite). WPF render tier donanım/efekt bütçesi için kullanılır. [Microsoft WPF donanım performansı](https://learn.microsoft.com/en-us/dotnet/desktop/wpf/advanced/optimizing-performance-taking-advantage-of-hardware).

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: kullanıcının kurulu tarama hatasının gerçek runtime nedeni, çok kullanıcılı Guardian/IPC/kasa migration davranışı, doğru saldırgan süreç korelasyonu ve düşük donanımda bağımsız kritik koruma henüz doğrulanmadı. Bu dilim kaynak ve inert regresyon kanıtıdır; ürünün Defender yerine geçtiği veya gerçek saldırıları otomatik güvenle temizlediği iddia edilmez.
