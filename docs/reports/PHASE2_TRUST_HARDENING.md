# Faz 2 güven çekirdeği — 2026-09-13

## Sonuç ve kapsam

İmza doğrulaması, hash önceliği, önbellek, yayıncı/yol güveni, güncelleme yetkilendirmesi ve ilgili test hataları düzeltildi. Ürün için genel tespit başarısı veya üretim hazırlığı iddiası yoktur. Mevcut kullanıcı değişiklikleri korunmuş, commit/push veya canlı servis kurulumu yapılmamıştır.

## Düzeltilen sorunlar

| Sorun | Değişiklik | Kanıt türü |
| --- | --- | --- |
| Sertifika zincirinin içerik imzası sayılması | WinTrust dosya ve katalog doğrulaması; gerçek yayıncı metadata'sı | Gerçek imzalı .NET host kopyasının içerik değişikliği BadDigest ile reddedildi; cmd.exe/notepad.exe katalog kontrolleri Windows ile uyumlu |
| Yayıncı/klasör adından güven atlaması | Tam isim eşleşmesi, dizin sınırı kontrolü, tam güven atlamalarının kaldırılması | Sentetik politika birim testleri |
| Hash kontrolünden önce imza/beyaz liste atlaması | Bilinen hash ve OS-blocked sonucu öncelikli | Sahte hash servisiyle karar birim testleri; canlı zararlı testi değildir |
| Hash aşamasının erken temiz önbellek yayımlaması | Yalnız tamamlanmış analizden cache yazımı | Hash aşaması sonrası cache boşluğu doğrulandı |
| Boyut/tarih korunarak cache'in eskimesi; tehdit bulgusunun konumla silinmesi | İçerik fingerprint'i ve güncel hash kontrolü; konumla temizleme kaldırıldı | Zararsız gerçek dosyalarla regresyon |
| İptal/hata durumunun temiz sonuca dönüşmesi | Hash/imza iptali aktarılır; başarısız gerçek zamanlı inceleme Unknown/Observe olur | İptal ve sahte hash-hatası birim testleri |
| Doğrulanmamış güncelleme, yol taşması, paket değişikliği | Sabitlenmiş RSA-PSS yayın anahtarı, sınırlı/sürümlü manifest, kilitli tekrar hash, hedefe özel geri alma | Geçici anahtar + sahte HTTP + gerçek geçici dosya I/O testleri |
| WPF testi timeout'u başarı sayıyordu | Join sonucu zorunlu; kaynak isimleri case-sensitive | XAML regresyon testleri |
| Null WPF Application uyarısı | Açık null kontrolü | Derleme |

## Test kanıtları

- İlk 9 yeni test düzeltme öncesi 9/9 başarısız oldu; hatalar yeniden üretildi.
- Ara sürümlerde 88/88 ve ardından 90/90 seçilmiş test geçti. Golden beşlisi bu çalışmalara dahildi. Son iki ek test bu eski sayıya dahil değildir.
- Son ana paket denemesinde `AegisPC.Tests.dll` Microsoft Defender tarafından `HackTool:Win64/PSWDump.MX!MTB` olarak karantinaya alındı (Operational 1116/1117). Test keşfi çalışmadı; çıkış kodu 0 olmasına rağmen bu çalışma başarılı sayılmadı. Önceki `phase2-regression.trx` bu boş denemeyle üzerine yazıldığı için eski başarılı koşunun kalıcı raporu olarak kullanılmamalıdır.
- Canlı müdahale/credential testlerini içermeyen ayrı `AegisPC.Trust.Tests` projesinde son kaynakla **35 geçti, 0 başarısız, 0 atlanan**. Sonuç: `tests/AegisPC.Trust.Tests/TestResults/phase2-final.trx`.
- `scripts/Test-TrustCore.ps1` test sayısını/TRX sonucunu ayrıca doğrular; test keşfi boşken exit code 0 dönmesini başarı saymaz. Script ile tekrar çalıştırma da 35/35 geçti; her koşu ayrı sonuç dizini kullanır.
- Bu 35 test; yayıncı/yol/iptal/hash-önceliği birim testleri, sahte HTTP ve geçici anahtarla güncelleme testleri, gerçek dosya cache testleri ve iki Windows Authenticode entegrasyon testinin karışımıdır. 35 gerçek zararlı senaryosu değildir.
- Defender kapatılmadı, istisna eklenmedi, karantina geri alınmadı. Algılamanın yanlış pozitif olduğu kanıtlanmış değildir; büyük test derlemesi ayrıca incelenmelidir.

## Performans ve yayın

Ara derlemede 157.480 baytlık .NET host dosyası üzerinde 100 içerik-doğrulamalı cache okuması: 38,00 ms duvar süresi, 46,875 ms süreç CPU artışı, yaklaşık 3,61 MiB working-set artışı. Tek sıcak-cache mikroölçümdür; eski sürümle kontrollü karşılaştırma değildir, tam tarama RAM/CPU/throughput sonucu sayılamaz. Güvenli cache artık dosya içeriğini okur; büyük dosyalarda maliyet artışı beklenir.

İnceleme yayınları `artifacts/phase2-review/app` ve `artifacts/phase2-review/service` altındadır. Masaüstü kısayolu halen `AegisPC_App/UltronDefender.exe` hedefindedir; canlı dağıtım değiştirilmemiştir. EXE apphost hash'i tek başına motor sürümünü kanıtlamaz; AegisPC.Security.dll de karşılaştırılmalıdır.

Son App ve Service Release publish komutları exit 0 ile tamamlandı. Kaynak derlemesi, App yayını ve Service yayınındaki `AegisPC.Security.dll` SHA-256 değerleri eşleşti: `93D2A5480211D16CF348AA0EE0D17BC1648FB48EFFB768AD8B05C3860DD1122C`.

## Şüphecilik ve Doğrulama Notu

Tam doğrulanamayanlar: bağımsız zararlı/temiz corpus başarısı, son kaynakla bütün büyük test paketi, aktif WPF/servis davranışı, sertifika iptal/çoklu katalog matrisi, tüm modüllerin muafiyetleri ve çok dosyalı/çökme-dayanıklı üretim güncellemesi. Üretim yayın anahtarı ve canlı güncelleyici entegrasyonu yoktur; güncelleme anahtar yokken kapalıdır. Kalıcı replay koruması, korumalı dizin yarışları ve sürümlü politika cache'i için [protokoldeki kalan işleri](../architecture/PHASE2_TRUST_PROTOCOL.md) takip edin.
