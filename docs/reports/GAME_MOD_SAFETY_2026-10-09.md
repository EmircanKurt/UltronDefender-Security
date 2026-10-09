# Açık tema ve oyun/mod güvenilirliği — 9 Ekim 2026

Bu değişiklik deneysel preview içindir; yeni oyun ekranı veya oyun klasörü güven muafiyeti eklenmedi. Defender, SCM, sürücü, boot ve otomatik müdahale kapsamı genişletilmedi.

Karar ayrımı [ReShade'ın resmî injector/unsigned add-on açıklaması](https://reshade.me/) ve [Microsoft'un malware/PUA ölçütleri](https://learn.microsoft.com/en-us/defender-xdr/criteria) ile karşılaştırıldı. Bir injector veya unsigned araç olmak tek başına malware kanıtı değildir; bütün HackTool kayıtları da zararsız sayılmaz.

## Kodlanan ve regresyonla doğrulanan değişiklikler

- Gerçek Wpf.Ui `MenuItems` / `FooterMenuItems` şablonu korunur. Tema paleti ortak yardımcıdan uygulanır; açık temanın koyu sidebar metni/ikonu hover, seçim, seçim+hover ve odak triggerlarında en az 4,5:1 kontrastla kontrol edilir. Light→Dark→Light ve geniş→dar→geniş geçişleri inert STA fixture'ında sınanır. Bu, canlı fare/DPI kabul testi değildir.
- Legacy risk API ortak motora adapte edilir; motor yoksa veya dosya kimliği değişmiş/erişilemiyor ise `Unknown`. Crack/keygen/patcher adı, yol, kaynaksız hash listesi ve sıradan paketleme özellikleri malware kararı ya da güven indirimi sağlamaz.
- Capability havuzu ölçülmüş özellik deduplikasyonundan sonra deterministiktir: en güçlü katkı + diğerlerinin dörtte biri, en fazla 25. Bağımsız kategori eşikleri korunur; sıradan W+X/entropi/packer/API bilgileri tek başına uyarı eşiğine ulaşmaz. Exact imza/provider kanıtı önceliğini korur; yüksek sezgisel puan otomatik karantina yetkisi değildir.
- Additive `SoftwareFindingClass` (0/1/2), hash-bağlı provenance, kural sürümü, kapsam ve bağımsız kanıt bilgisi Core→Contracts bağımlılığı eklemeden sonuç/RT/IPC/cache yoluna taşınır. Eski kayıtlar yeniden sınıflandırılmaz.
- `ShowPotentiallyUnwantedToolFindings=false` yalnız yerel sunum ayarıdır. Gerçek ayar view modelinde kaydetme servis patch'i veya policy revision değişimi yapmaz. Yalnız güncel, tamamlanmış, doğrulanmış saf tool-only kayıt gizlenebilir; malware/karışık/eksik/legacy kayıtlar görünür kalır. Ham raporlar korunur. Sağlık ve malware sayaçları bu ayarın açık/kapalı olmasından etkilenmez.
- Tool-only feed için deployment publisher key henüz provision edilmediğinden gerçek üçüncü taraf sınıflama akışı **kapalıdır**. Sentetik provenance testi canlı feed doğrulaması değildir. Ürün keygen/crack dosyalarını otomatik güvenli ilan etmez.
- ZIP/JAR üyeleri dosyaya çıkarılmadan akış halinde hash'lenir. Ortak script, YARA ve bounded Deep PE static mapping kullanılır; üye hash/rota dış arşiv kimliğinden ayrı kalır. YARA raw kayıtları tutulur, ortak evidence ikinci kez puanlanmaz. Arşiv içi Authenticode, diğer dosya tabanlı PE/davranış adaptörleri ve büyük/şifreli/bozuk/bütçe dışı üyeler kısmi kapsamdır; temiz diye gösterilmez. Tüm PE pipeline'ı kapsayıcı içinde henüz eşit değildir.
- Cache geçerliliği kural sürümü + intel identity + SHA-256 + tam kapsam ister. Legacy/partial/Unknown/bypass kayıt tekrar incelenir. Service path-only lookup boyut/tarih aynı olsa bile gerçek içeriği hash'ler; eşit uzunlukta içerik değiştirme regresyonu eklenmiştir.

## Test kanıtı ve henüz kapanmayan kapılar

Yerel geniş benign allowlist son turunda **574 passed / 0 failed / 0 skipped** (`audited-final/benign-preview.trx`). Değişmez aday turunun sonucu ayrıca kaydedilecektir. İlk RED karar testlerinde üç hata görülüp düzeltildi. İki eski testin motor yokken temiz beklentisi, onaylı `Unknown` sözleşmesine göre gerekçelendirilerek değiştirildi; bağımsız malware eşikleri zayıflatılmadı.

Testler ayrı türler içerir: sentetik karar/serialization testleri, gerçek zararsız dosya I/O ve arşiv fixture'ları, native WPF off-screen kontrolleri. Toplam, malware yakalama oranı veya gerçek oyun/mod yanlış-alarm oranı değildir. Canlı malware/crack örneği indirilmedi, içerik çalıştırılmadı, günlük PC'de geniş lab suite çalıştırılmadı.

Gerçek korpus kapısı henüz **bekliyor**: en az 30 benzersiz resmî zararsız payload, altı aile, kaynak/sürüm/lisans/hash manifesti ve tamamen ayrılmış bir holdout aile gerekir. [Manifest şablonu](../testing/game-mod-corpus.template.json) bilinçli olarak boştur; sentetik fixture'lar bu sayıyı doldurmaz. `scripts/Verify-GameModPilotEvidence.ps1` yalnız kayıtları ve dosya hash'lerini çevrimdışı doğrular; indirip çalıştırmaz ve origin/lisans beyanını bağımsız olarak kanıtlamaz.

Aynı korpus/kapsam/makinede baseline ve aday için beş soğuk + beş sıcak ölçüm de **bekliyor**. Süre, normalize CPU, tepe çalışma kümesi, kuyruk p95 ve kapsam kaybı kaydedilmeli; medyan süre >%10 veya tepe bellek >%15 kötüleşirse inceleme olmadan yayın kapısı geçmez. Sadece process restart, soğuk disk-cache ölçümü olarak kabul edilmez. Bu aşamada gerçek korpus performans iyileşmesi iddiası yoktur.

## Geri dönüş ve VirtualBox pilotu

Değişmez kaynak/paket/hash manifesti ve native UI ile motor için ayrı review dönüş noktaları hazırlanır. Yerel portable aktarım yalnız publish manifestindeki uygulama dosyalarını kapsar; `Service/Helpers`, kullanıcı ayarları, log, veritabanı ve karantina değişmez. Kilit varsa uygulama zorla kapatılmaz. Önceki dosyalar hash'li yedekte tutulur; rollback yalnız kendi dağıtım hash'i hâlâ eşleşen dosyalara uygulanabilir.

İzole Windows 10/11 x64 VM'de snapshot alıp benign kurulum/tarama/iptal/kaldırma/rollback ve servis uyumu sınanmalıdır. Önceki kurulu servis yeni RT semantiğini otomatik almaz. Preview setup servis/driver/Defender kurmaz veya başlatmaz. İmzalama, gerçek korpus, fiziksel DPI/input ve VM kapıları tamamlanmadan kararlı sürüm/otomatik acil politika ilan edilmez.

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: gerçek oyun/mod korpusundaki yanlış-alarm oranı ve performans, kapsayıcı içindeki bütün PE/adaptör eşitliği, kullanıcının canlı hover/DPI davranışı ve native kurulum/rollback/RT işlemleri henüz doğrulanmadı. Yerel kaynak testleri, bunların geçtiği anlamına gelmez.
