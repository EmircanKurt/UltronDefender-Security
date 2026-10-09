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

Son değişmez adayda seçili benign allowlist: **580 passed / 0 failed / 0 skipped**. Hem tüm çözüm hem Review projesi Release/warnings-as-errors derlemesi: **0 hata / 0 uyarı**. Önceki 574 turuna altı inert endpoint uyumluluk testi eklendi. İlk RED karar testlerinde üç hata görülüp düzeltildi. İki eski testin motor yokken temiz beklentisi, onaylı `Unknown` sözleşmesine göre gerekçelendirilerek değiştirildi; bağımsız malware eşikleri zayıflatılmadı.

Geniş çözüm denetimi ayrıca eski public test paketinde 15 derleme uyumsuzluğu buldu: kaldırılmış `DetectCategory` için 12 çağrı ve public alt kümede bulunmayan policy fixture'larının üç tipi. Eski ad/family sınıflandırıcısı geri açılmadı; test, bu API'nin yokluğunu doğruluyor. Tam ağaçta mevcut policy fixture'ları korunur; yalnız eksik oldukları public alt kümede mevcut in-memory Review yardımcıları linklenir. Başka işlemin working-tree test ekleri ezilmedi. Eski ağ/import beklentili lab testlerinin tümü günlük PC'de çalıştırılmadı; bunların runtime kabulü bu sayıdan çıkarılamaz.

Yeni altı test sınıfının 42 vakası aşağıdadır; 580 toplamının içindedir, ek bir toplam değildir. Ayrı UI-only dönüş noktasında 37 test geçti (aynı native menü testi bu turda da vardır).

| Grup | Vaka | Test türü |
|---|---:|---|
| Native sidebar | 1 | Gerçek Wpf.Ui kontrolleri, off-screen STA; birçok durum tek vaka içinde |
| Oyun/mod kanıtları | 6 | Sentetik puan/deduplikasyon ve inert dosya kimliği fixture'ları |
| İsteğe bağlı kategori | 13 | Metadata/serialization/karar ve fake settings/IPC sınırı |
| Sürümlü cache | 8 | Sentetik karar + benign disk/cache/JSON fixture'ları |
| ZIP/JAR ortak kurallar | 8 | Üretilmiş benign dosyalar ve kapsayıcılar; gerçek oyun korpusu değil |
| Legacy endpoint sınırı | 6 | Fake HTTP/settings hiç çağrılmaz; force/bootstrap/iptal/reflection |

Testler ayrı türler içerir: sentetik karar/serialization testleri, gerçek zararsız dosya I/O ve arşiv fixture'ları, native WPF off-screen kontrolleri. Toplam, malware yakalama oranı veya gerçek oyun/mod yanlış-alarm oranı değildir. Canlı malware/crack örneği indirilmedi, içerik çalıştırılmadı, günlük PC'de geniş lab suite çalıştırılmadı.

Gerçek korpus kapısı henüz **bekliyor**: en az 30 benzersiz resmî zararsız payload, altı aile, kaynak/sürüm/lisans/hash manifesti ve tamamen ayrılmış bir holdout aile gerekir. [Manifest şablonu](../testing/game-mod-corpus.template.json) bilinçli olarak boştur; sentetik fixture'lar bu sayıyı doldurmaz. `scripts/Verify-GameModPilotEvidence.ps1` yalnız kayıtları ve dosya hash'lerini çevrimdışı doğrular; indirip çalıştırmaz ve origin/lisans beyanını bağımsız olarak kanıtlamaz.

Aynı korpus/kapsam/makinede baseline ve aday için beş soğuk + beş sıcak ölçüm de **bekliyor**. Süre, normalize CPU, tepe çalışma kümesi, kuyruk p95 ve kapsam kaybı kaydedilmeli; medyan süre >%10 veya tepe bellek >%15 kötüleşirse inceleme olmadan yayın kapısı geçmez. Sadece process restart, soğuk disk-cache ölçümü olarak kabul edilmez. Bu aşamada gerçek korpus performans iyileşmesi iddiası yoktur.

## Geri dönüş ve VirtualBox pilotu

Değişmez kaynak/paket/hash manifesti ve native UI ile motor için ayrı review dönüş noktaları hazırlanır. Yerel portable aktarım yalnız publish manifestindeki uygulama dosyalarını kapsar; `Service/Helpers`, kullanıcı ayarları, log, veritabanı ve karantina değişmez. Kilit varsa uygulama zorla kapatılmaz. Önceki dosyalar hash'li yedekte tutulur; rollback yalnız kendi dağıtım hash'i hâlâ eşleşen dosyalara uygulanabilir.

Yerel app-only aktarım doğrulandı: 545 uygulama/uyumlu alias dosyası ve 436 değişmeyen service/helper ikilisi; masaüstü kısayolunun hedefi 3.2.3-preview. Uygulama başlatılmadı. İnert rollback denetiminde kilitli dosya önceden reddedildi; sonradan değişmiş dosya hiçbir restore yazımı olmadan reddedildi; aktarım ortasındaki I/O hatası eski içerikleri geri getirdi ve yeni dosyaları geri kazanılabilir alana taşıdı. Bunlar native VM kurulum/rollback testi değildir.

İncelemeler: [UI PR10](https://github.com/EmircanKurt/UltronDefender-Security/pull/10) ve onun üzerine bağımlı [motor PR11](https://github.com/EmircanKurt/UltronDefender-Security/pull/11). Draft'tır; main/stable otomatik merge edilmedi. Test-only son uyumluluk değişiklikleri paket/runtime kaynağını değiştirmez.

İmzasız preview setup: `UltronDefenderSetup-3.2.3-preview.20261009.exe`, 126094895 bayt. SHA-256: `467B7D8896E82B3B7F5EF7944DCF0B7FFF77F528426E950C6689C18E17A01D1A`. Derlendi, çalıştırılmadı; public/stable release ilan edilmedi.

İzole Windows 10/11 x64 VM'de snapshot alıp benign kurulum/tarama/iptal/kaldırma/rollback ve servis uyumu sınanmalıdır. Önceki kurulu servis yeni RT semantiğini otomatik almaz. Preview setup servis/driver/Defender kurmaz veya başlatmaz. İmzalama, gerçek korpus, fiziksel DPI/input ve VM kapıları tamamlanmadan kararlı sürüm/otomatik acil politika ilan edilmez.

Pilot sırası: hash'i kontrol et → temiz VM snapshot'ı al → preview setup'ı VM içinde kur → açık/koyu menü hover/seçim/klavye odağı ve %100/%125/%150 DPI'ı dene → yalnız resmî benign korpusta hızlı/tam/özel tarama, duraklat/iptal ve kapsam raporlarını kaydet → kaldırma ve VM snapshot geri dönüşünü dene. RT servis/driver testi ayrı yetkilendirilmiş VM aşamasıdır; bağlantısı olmayan servis aktif gösterilmemelidir. Host Defender kapatılmaz, crack sitesi veya canlı malware kullanılmaz.

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: gerçek oyun/mod korpusundaki yanlış-alarm oranı ve performans, kapsayıcı içindeki bütün PE/adaptör eşitliği, kullanıcının canlı hover/DPI davranışı ve native kurulum/rollback/RT işlemleri henüz doğrulanmadı. Yerel kaynak testleri, bunların geçtiği anlamına gelmez.
