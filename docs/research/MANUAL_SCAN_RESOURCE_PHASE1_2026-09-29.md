# Manuel tarama kaynak verimi — ilk uygulama dilimi (2026-09-29)

## Doğrulandı

- Hızlı/Tam taramada kaynak seçim penceresi her seferinde açılır. Son tercih yalnız “Son seçimimi hatırla” etkinse önseçilir; ayar dosyası yazılamazsa kullanıcının onayladığı tarama yine başlar. Bu akış derlendi; native pencere etkileşimi ayrıca pilotlanmadı.
- Tarama ilerlemesinde faz, gerçek analiz işçisi sayısı, etkin işçi sınırı ve bekleyen dosya sayısı taşınır. Başlangıç kontrolleri ve dosya kuyruğu süreleri ayrı loglanır.
- Zararsız, sentetik kuyruk testlerinde tek işçi sınırı, bekleyen dosya sayısı ve iptal sonrası sayaç temizliği doğrulandı. Seçili karma Release regresyonu 476/476; bunun tümü güvenlik entegrasyon testi değildir. Review derlemesi `--warnaserror` ile 0 uyarı/0 hata.
- Aynı 80 × 16 KiB zararsız dosya mikro-ölçümü öncesinde Auto 253 ms, Maximum 255 ms; sonrasında Auto 223 ms, Maximum 231 ms ölçüldü. Tek koşu ve küçük/sıcak dosyalar nedeniyle fark bir hız kazanımı kanıtı değildir; Maximum burada Auto'dan hızlı değildi. Bellek bütçesi gerçek RSS hedefi değil, tavsiye edilen üst sınırdır.

## Henüz uygulanmayan performans işi

1. SSD/HDD/USB hedeflerini tarama sırasında ayrı ölçmek ve çoklu birimlerde tek başlangıç diski sınıflandırmasının yanlış uygulanmasını gidermek. HDD paralelliğini körlemesine artırmak yerine karışık boyutta dosyalarla p50/p95 süre, MB/s, CPU, gerçek tepe RSS ve sistem tepkiselliğini kıyaslamak.
2. Üretim hattında okunmayan `MaxScanConcurrency` ayarını ya açıkça kaldırmak ya da güvenlik sınırları içinde etkili, isteğe bağlı üst sınır olarak bağlamak. Şu an kullanıcı bu değeri değiştirse de tarama işçi sayısını değiştirmez.
3. Seçim penceresi, Quick/Full fazları ve kurulu uygulama davranışını Windows 10/11 SSD/HDD ve düşük RAM pilotlarında uçtan uca ölçmek. Windows 7, kernel engelleme veya AV tespit oranı için bu çalışma kanıt üretmez.

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: uzun gerçek disk taramasındaki ana darboğazın dosya yürütme, hash/PE/YARA, disk veya başlangıç kontrollerinden hangisi olduğu; ölçüm ve cihaz matrisi olmadan CPU/RAM kullanımını zorla yükseltmek daha hızlı tarama garantilemez.

## 2026-09-30 devam notu

Yukarıdaki 476/476 ve okunmayan `MaxScanConcurrency` maddeleri 29 Eylül tarihli ilk aşamanın anlık durumudur. Sonraki dilimde yanıltıcı ayar kaldırıldı; manuel tarama girişleri atomik sahiplikle birleştirildi, örneklenmiş tepe RSS eklendi. Güncel doğrulama ve açık yayın kapıları için [ilk güvenilirlik uygulama raporuna](AV_RELIABILITY_STAGE1_2026-09-30.md) bakın. Bu değişiklikler ölçülmüş hız kazancı değildir.
