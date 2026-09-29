# Bildirim doğruluğu ve sade kart — 27 Eylül 2026

## Doğrulanan hata ve düzeltmeler

- `WindowsToastNotificationService`: üç Warning/Error bildirimi üç virüs sayılıyordu; hata rengi veya “karantinaya alınamadı” metni tüm grubu başarılı karantina gibi gösteriyordu. Artık sayı **bildirim sayısı**, özgün başlık/sonuç korunuyor; renk güvenlik kanıtı değil.
- `NotificationAggregator`: aynı olay tekrar sayılıyordu, her karantina olmayan olay engellenmiş sayılıyordu. Tekil ad/yol/eylem anahtarı ve nötr güvenlik-olayı özeti eklendi. Kritik seviye başarı kanıtı sayılmıyor.
- Paralel aynı bildirim atomik tekilleştiriliyor; dosya adlarındaki rakamlar silinmiyor. Yeni farklı gruplar genel 15 dakika engeline takılmıyor. Dispose bekleyen bildirimi göstermiyor. Rutin tarama başlığını taşıyan gerçek hata bastırılmıyor.
- App'in ikinci tarama-sonu bildirimi kaldırıldı; ScanViewModel sonuç raporlamasını sahipleniyor. ETW algılama olayı sonlandırma gerçekleşmiş gibi anlatılmıyor. Fidye olayında yalnız `ProcessTerminated` gerçek sonucu bildiriliyor.
- Dashboard başlangıç/gerçek-zamanlı sayaçları yalnız doğrulanmış karantina eylemine göre değişiyor. Karışık grupta başarılı karantina ile şüpheli gözlem ayrı sayılıyor. IPC'de `Resolved` artık karantina başarısı sayılmıyor.
- Startup sweep başarısız karantinada `QUARANTINE_FAILED` ve başarısız denetim sonucu yazıyor. Saatli tarama temiz/çözülmüş/istisnalı bulguyu yeniden bildirmiyor; başarısız/iptal tarama tamamlanmış gibi bildirilmiyor.
- Üretimde kalan sentetik test işaretçisi kaldırıldı. EICAR adını içeren belge artık test dosyası sayılmıyor. Eski kodlanmış sözde tam imza aslında 60 bayttı; resmî 68 baytlık içerikle düzeltildi. Tam içerik ve izinli son boşluklar, toplam en fazla 128 bayt olacak şekilde doğrulanıyor. Büyük dosyanın son parçası bütün dosya sanılmıyor; arşiv üyeleri de aynı sınırla kontrol ediliyor. Bilinen hash ve canonical bellek/arşiv üyesi testi korunuyor. Ölçüt: [EICAR resmî test dosyası tanımı](https://www.eicar.org/download-anti-malware-testfile/).

Dosya adı/uzantısı bazlı yeni güven muafiyeti eklenmedi. Gerçek bulguları saklamak için bildirimler topluca kapatılmadı.

## Sade tasarım

380×205 kart; küçük Ultron başlığı, okunabilir özgün bildirim, gerektiğinde kaydırılabilir ayrıntı, tek **Ayrıntılar** düğmesi ve kapatma. Büyük kalkan/rozet, otomatik başarı alt yazısı, kayma ve nabız animasyonu kaldırıldı. Kart klavye odağını çalmıyor; üzerine gelince kapanma sayacı duruyor. Tasarım XAML derlemesi ve kaynak kontrolleriyle doğrulandı, kullanıcı ekranında görsel pilot yapılmadı.

## Test kanıtı

- İlk RED: `notification-red.trx` 29 başarısız / 3 başarılı; ek arka plan ve bakım testinde birer beklenen başarısızlık, UX testlerinde 2 beklenen başarısızlık.
- Son GREEN: `TestResults/NotificationReview/notification-release-verified.trx`, Release **389/389**, 0 başarısız. Sıfır uyarı/hata ile ayrı `dotnet build --warnaserror` doğrulandı.
- Önceki 335 karma regresyona 54 kontrol eklendi: 12 sahte bildirim-alıcılı birim testi, 16 UI/üretici kaynak veya saf-özet kontrolü, 10 imza kontrolü, 4 zamanlı-bildirim birim testi ve 12 mevcut saf başlık/yönlendirme testi. İmza grubunun bir testi zararsız belgeyi gerçek disk I/O ile motor üzerinden inceler; diğerleri bellek/kurgu kontrolleridir. Bu sayılar gerçek zararlı yazılım etkinlik testi değildir.
- Ana test projesinin tamamı çalıştırılmadı. Review açık kaynak listesi kullanıldı; fiziksel EICAR oluşturan Golden01, canlı kimlik bilgisi/süreç sonlandırma ve kurulum testleri kapsam dışında tutuldu. Fiziksel test virüsü indirilmedi/oluşturulmadı, canlı süreç sonlandırılmadı, Defender ayarları değiştirilmedi.

## Dağıtım ve sınırlar

Yeni paket `artifacts/notification-fix-2026-09-27/UltronDefenderSetup.exe` altında oluşturuldu. App/Service/Helper self-contained win-x64 Release yayımlaması ve Inno Setup derlemesi 69,1 saniyede tamamlandı. Paket 123.340.007 bayt, **NotSigned**, SHA-256 `388119147E0AA01B60D798698F07403E7281622B53843B962F6BC2274C36EC2F`. Yayımlanan App DLL SHA-256 `5092B72054876C5061B46FBB1090E6E25B3DAC974ADBA57FCAD61B577D43B3F0`; Service DLL `1EBB144307B84DB2C157A6FD241F14D7A78F2F599A96A2DAE737342970C803DD`. Önceki 3.2.1 paket/PR bu yerel düzeltmeyi içermez; bu tur commit/push veya kurulum yapılmadı.

Masaüstü kısayolu hâlâ `AegisPC_App/UltronDefender.exe` dosyasına gidiyor: 26.09.2026 21:20:20, SHA-256 `76CDEBF40462A0556659209A75FAABC974741F79873BC4019A0C30A96CB1C5B8`. Eski kurulu/taşınabilir uygulama otomatik değiştirilmedi.

## Şüphecilik ve Doğrulama Notu

Şu an tam doğrulayamadığım nokta kullanıcı ekranında yeni kartın görünümü ve kurulu servis ile uçtan uca bildirim akışıdır. Diğer sezgisel motor/YARA kuralları ve eski native kernel ad-bazlı kurallar için sıfır yanlış pozitif iddiası yoktur. Gerçek tespit etkinliği, Windows cihaz matrisi, paket imzalama ve Defender temizliği bu testlerle kanıtlanmaz.
