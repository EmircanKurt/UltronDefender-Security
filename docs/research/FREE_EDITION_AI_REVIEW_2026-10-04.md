# Ücretsiz sürüm, AI regresyonları ve GitHub açıklaması — 2026-10-04

## Uygulanan dar değişiklik

Kullanıcı mevcut ürünü ücretsiz tutmak istedi. Kaynakta bulunan sabit örnek PRO lisans anahtarı, sabit kalan gün alanı ve bunları panoya kopyalayan komut kaldırıldı. Bunlar gerçek bir ürün aktivasyon doğrulayıcısı değildi; aranan App XAML dosyalarında görünür kullanım bulunmadı. Dolayısıyla kurulu ekrandan bir ödeme sayfasının kaldırıldığı iddia edilmez. Ücretli sürüm veya ödeme sistemi eklenmedi.

Windows koruma hizmeti ve koruma düğmeleri kaldırılmadı. Hizmet arka plan koruma/IPC/kasa mimarisinin teknik parçasıdır, ücret şartı değildir. Kasa şifreleme anahtarları, güncelleme imza doğrulaması ve üçüncü taraf API kimlikleri ürün aktivasyonundan ayrıdır; bunlara dokunulmadı. Hizmetten doğrulanmış durum alınamıyorsa sağlık uyarısı korunur; ücretsiz olması etkin koruma kanıtı değildir.

## Bu turda gerçekten çalıştırılan testler

Release çözüm ve Review projesi derlemeleri `--no-restore -warnaserror` ile 0 hata / 0 uyarı verdi. Seçili zararsız Review koşusu normal kullanıcı bağlamında **939 geçti, 1 atlandı, 0 başarısız; toplam 940** verdi.

| Review içindeki grup | Geçen vaka | Ölçülen kapsam |
| --- | ---: | --- |
| UltronAiTests | 13 | Eksik/bozuk veri, içerik/uzantı ayrımı, sınırlı PE özellikleri, iptal; öncelik puanı otomatik müdahale yetkisi veya olasılık değildir. |
| UltronChiefSafetyTests | 13 | Tekilleştirme, sahte/eski izin, SID/hedef/replay değişimi, istatistik ve sağlık politikası; eylem adaptörleri inerttir. |
| UltronAiShieldBackendTests | 13 | İsteğe bağlı inceleme kapısı, eski sonuçları atma, rol/ayar politikası; bağımsız imza kanıtı kapatılmaz. |
| UltronAiShieldUiTests | 16 | İki onay ve hizmet gözlemine bağlı düğme akışı; canlı kurulu UI testi değildir. |
| UiAiPreferenceSyncTests | 14 | Sayfadan bağımsız tercih eşitlemesi, eski/uyumsuz gözlem ve hata senaryoları; sahte IPC/geçici ayar dosyası kullanılır. |
| FreeEditionPresentationTests | 2 | Derlenen VM'de eski lisans API'si yok; kaynak App XAML'ında eski lisans bağları yok. |

AI ile ilgili ilk beş grup **69/69** geçti ve 939 toplamının içindedir; ayrıca toplanmaz. Bunlar güvenlik birim/politika ve altyapı/UI akış testleridir, gerçek zararlı korpusu veya yakalama oranı değildir. Ultron AI bir LLM veya kalibre edilmiş olasılık modeli değildir. Guardian'ın gerçek üretim müdahalesi ve bağımsız kritik koruma sahipliği bu testlerle doğrulanmaz.

İlk kısıtlı ortam koşusu 878 geçti / 61 başarısız / 1 atlandı verdi: 58 doğrudan ACL yetki hatası, 1 kullanıcı-profili DPAPI hatası ve 2 farklı hata yolu/assert sonucu. Aynı kaynak ve filtre normal kullanıcı bağlamında yeniden koşuldu ve bu 61 vaka geçti; koruma/ACL kodu gevşetilmedi. Her iki TRX korundu:

- `TestResults/FreeEdition2026-10-04/free-edition-review.trx`: başarısız kısıtlı ortam koşusu.
- `TestResults/FreeEdition2026-10-04/free-edition-user-review.trx`: son normal kullanıcı koşusu.

Filtre: `FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests`. Fiziksel EICAR ve canlı süreç/kimlik bilgisi testleri çalıştırılmadı. Golden02–05 geçti; Golden01 çalıştırılmadığı için beşli Golden paketin tamamı geçti denmez. Atlanan `LegacyInitializationLockCannotRedirectCreationOutsideVault` izole VM-yetki kapısıdır, geçmiş sayılmaz. Trust projesi bu tur tekrar koşulmadı; önceki 35/35 sonucu tarihsel kanıttır.

## GitHub'daki mevcut durum

[Deponun main README'si](https://github.com/EmircanKurt/UltronDefender-Security/blob/main/README.md) GitHub'ın herkese açık API'sinden salt okunur alındı. Hazır yayın, ticari seviyede koruma, sıfır yanlış pozitif ve anında engelleme iddiaları güncel yerel kanıtla desteklenmiyor. 616 test rozeti güncel kaynak test sayısı değildir ve hiçbir test sayısı tek başına antivirüs etkinlik oranı göstermez. Yerel README bu sınırlamaları ve ücretsiz sürümü açıklar; main henüz güncellenmedi.

GitHub About açıklaması zaten deneysel Windows 10/11 kullanıcı-modu araç ve doğrulanmamış kernel korumasını belirtiyor; sırf eski README yanlış diye About'un da yanlış olduğu varsayılmadı. Devam turunda GitHub bağlantısı açıldı: bağlı hesap `EmircanKurt`, depo izinleri `push/admin=true` olarak doğrulandı. Kullanıcı test edilen kodların da ayrı taslak PR'a dahil edilmesini onayladı. Önceki PR1 ve PR2 taslaktır; PR1 birleştirme çatışması taşıyor. Bu kaynak dilimi PR2'nin `codex/av-reliability-stage1` dalını temel alan ayrı dalda incelenecek; main'e doğrudan veya force-push yapılmayacak. Main README ancak incelenmiş değişiklikler birleştirildikten sonra güncellenir.

## Görseller ve ayrı yayın

Bu tur kurulu antivirüs arayüzü otomatik açılmadı, kontrol edilmedi veya ekran görüntüsü alınmadı. Bilgisayar kullanım yönergeleri antivirüs uygulamalarının otomasyonunu yasaklar. Kullanıcının paylaşacağı güncel ekran görüntüleri, kişisel yollar/kayıtlar kontrol edildikten sonra dokümantasyon için kullanılabilir. Kaynak/offscreen render görselleri yalnız önizleme etiketiyle kullanılabilir; gerçek çalışan koruma kanıtı değildir.

App, `artifacts/free-edition-2026-10-04/app` altında ayrı framework-dependent Release çıktısı olarak yayımlandı; .NET 8 Desktop Runtime gerektirir. Kurulu ürün, servis, masaüstü kısayolu, mevcut taşınabilir klasör ve kurulum EXE'si değiştirilmedi. Paket Authenticode imzalı değildir. Apphost EXE hash'i önceki sürümle aynı kalabildiğinden asıl kaynak eşleşmesi managed DLL ile doğrulandı:

- EXE UTC tarihi: `2026-10-04 18:36:01`; SHA-256 `6B1E9F1F720245D2D7DC2D360721242EDFB18D1061507FE63B7F0B78CAFF7661`.
- App DLL SHA-256: `C9A465A243496716F70D6F0C7995F3D2D81CADD6DC23AC04A69B66DA98FB48B5`; testin referans aldığı Release DLL ile eşleşti.

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: gerçek kurulu servis/arayüz davranışı, devam eden tarama başarısızlığının runtime nedeni ve gerçek zararlı/temiz korpus etkinliği henüz doğrulanmadı. Yeni gerçek uygulama ekran görüntüleri ve bu kaynak için GitHub CI sonucu da henüz yok. Bu dilim kaynak temizliği, güvenli regresyon ve ayrı build çıktısıdır; üretim yayını veya Defender'ın yerine geçebilen ürün değildir.
