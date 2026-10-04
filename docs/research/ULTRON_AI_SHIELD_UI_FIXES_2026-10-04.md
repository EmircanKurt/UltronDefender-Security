# Ultron AI anahtarı, kaydırma ve tarama tanılaması — 2026-10-04

## Sonuç ve gerçek kurulum durumu

Kaynak ve güvenli regresyonlar güncellendi. **Kurulu sistem değiştirilmedi; bağımsız Guardian veya gerçek zamanlı koruma hazır/etkin ilan edilmedi.**

Normal kullanıcı bağlamında, sandbox dışı salt-okunur `Get-Service` doğrulaması: `AegisPC Protection Service`, `UltronDefenderService`, `AegisPCProtectionService` üçü de `NoServiceFoundForGivenName` döndürdü. Bu uygulamanın beklediği koruma hizmeti bu bilgisayarda bulunamadı. Fotoğraftaki güncel koruma durumu uyarısı bir virüs bildirimi değildir. Arayüzün açık anahtarları hizmetin çalıştığına delil olmaz. Hizmet kurulumu/başlatılması bu tur yapılmadı; kontrollü pilot ve ayrı onay gerektirir.

## Test edildi ve doğrulandı

| Alan | Uygulama | Kanıt/sınır |
|---|---|---|
| Ultron AI anahtarı | Kalkanlar bölümünde ek yerel inceleme; kapatırken iki ayrı açık onay, varsayılan Hayır | Mouse/Space/assistive Toggle aynı komuta gider; onay/servis yanıtı beklerken gösterge değişmez |
| Gerçek uygulama | Doğrulanmış yönetici IPC komutları, canlı plugin tercih getter'ı, nullable gözlenen durum | Eski/bağlı olmayan hizmet başarı sayılmaz; hash/imza/AMSI/Guardian izin doğrulaması kapanmaz |
| Uyarı | Bağlantısız/eski-uyumsuz/bayat/kısmi sağlık ayrımı ve Durumu Yenile | Uyarı gizlenmedi; fresh degraded kapsam da görünür |
| Tercih sürekliliği | Ayarlar sayfasından bağımsız servis gözlem eşitlemesi, yerel kalıcı snapshot, revision yenileme | Tek worker/son durum yuvası, hata/retry ve abonelik temizliği; sahte/eskimiş gözlem uygulanmaz |
| Kaydırma | Sayfa kendi viewport'unu yönetir; dış navigation kaydırıcısı kapatılır, hareketsiz olay tüketilmez | Gerçek offscreen WPF-UI Frame reproducer ve gerçek ScrollViewer offset testleri; sanallaştırılmış listeler native scrolling kullanır |
| Ağ anahtarı | Hizmet yanıtından önce başarı/yerel etkinlik/audit üretilmez | Yalnız mevcut DNS/ağ yardımcı katmanı; tüm ağ akışı incelemesi değildir |
| Bağlı olmayan kontroller | Ayrı süreç ve oyun/sandbox anahtarları açıklamayla pasif | Çalışmayan anahtar koruma gibi sunulmaz; ortak dosya/ETW incelemesi kaldırılmadı |
| Tanılama | App ILogger sağlayıcısı ve başlangıç Serilog bağlantısı, MVID sürüm izi | Kullanıcı LocalAppData/UltronDefender/Logs, 1 MiB × 10 dönen dosya; yol/komut/ham exception metni yerine kod/tip/metot/correlation |
| Eski raporlar | Başlangıç zamanı olmayan kayıt açıkça eksik; dosya hata sayısı motor hatasından ayrı | Legacy kaydın nedeni veya zamanı uydurulmaz; default tarih üzerinden binlerce yıllık süre hesaplanmaz |

Ultron AI burada **yerel statik ek incelemedir**: yüksek puan zararlı olasılığı, kesin malware, bağımsız Guardian veya otomatik acil müdahale değildir. Kapalıyken bu isteğe bağlı inceleme yapılmaz; diğer güvenlik katmanları ayrıca yönetilir. “Kapatırsanız sisteminize her türlü işlem yapılabilir” şeklinde yanlış bir garanti/tehdit metni eklenmedi.

## Tarama başarısızlığında bilinmeyen kısım

En son yerel runtime geçmişi: `2026-10-04T17:51:03Z`, `Failed`, 53.151 incelenen öğe, 0 dosya hatası, `StartedAt=default`, `FailureInfo=null`. Aynı gün daha eski kayıtta 52.906 öğe vardı. Günlükte bu taramanın fatal istisnası bulunmadı. Eski 27 Eylül AuditLogs hatası bugünün nedeni kabul edilmedi.

Taşınabilir `AegisPC_App/UltronDefender.dll` güncel testli kaynak derlemesiyle eşleşmiyor. Bu, gerçekten başlatılan yolun o klasör olduğunu kanıtlamaz; host process yolu doğrulanmadı. Kaynakta somut bir tanılama hatası vardı: App `AddLogging()` sağlayıcısızdı ve statik Serilog logger kurulmamıştı. Yeni provider gerçek koordinatörün sentetik hatasını diske kod/correlation ile ulaştıran testten geçti. **53.151 öğede duran taramanın asıl runtime sebebi henüz bulunmuş veya düzeltilmiş sayılmaz.** Yeni tanılamalı uygulamayla tekrar ve yeni Failed raporu gerekir.

## Son doğrulama

- Solution, Review, Trust Release: 0 hata / 0 uyarı.
- Yeni hedefli kontroller: **57/57**, `TestResults/UltronShieldUi2026-10-04/shield-targeted-merged.trx`.
- Seçili güvenli Review: **937 geçti / 1 VM yetki testi atlandı / 0 başarısız, 938 toplam**, `shield-review-final.trx`.
- Trust: **35/35**, `shield-trust-final.trx`; Review ile ortak vakalar toplanmaz.
- Yeni vakalar: UI/onay/ağ 16, backend 13, wheel/viewport 10, log/legacy report 4, global tercih eşitleme 14. Bunlar mock/temp/inert UI ve güvenlik birim/altyapı testleridir; malware korpusu/etkinlik ölçümü değildir.
- Atlanan eski test symlink yetkisi gerektirir; host politikası değiştirilmedi. Whole main DLL canlı kill/credential/EICAR testleri çalıştırılmadı. Canlı UI/global input, gerçek SYSTEM IPC, gerçek kasa, servis kurulumu, fiziksel USB/HID veya Defender ayarı değişmedi.

Kaydırma temel davranışı [WPF-UI 4.3 resmi kaynak](https://raw.githubusercontent.com/lepoco/wpfui/4.3.0/src/Wpf.Ui/Controls/NavigationView/NavigationViewContentPresenter.cs) ile; Automation Toggle'ın özel komuta yönlendirilmesi [Microsoft WPF kaynağı](https://raw.githubusercontent.com/dotnet/wpf/main/src/Microsoft.DotNet.Wpf/src/PresentationFramework/System/Windows/Automation/Peers/ToggleButtonAutomationPeer.cs) ile karşılaştırıldı. Kaydırma kaybının bu uygulamadaki ilişkisi ayrıca inert viewport testinde yeniden üretildi.

## Ayrı yayın — kurulum değil

App ve Service framework-dependent Release publish exit0: `artifacts/ai-shield-ui-fixes-2026-10-04/app` ve `service`. Windows .NET 8 Desktop Runtime gerekir. Paket **NotSigned**, çalıştırılmadı. Eski portable klasör, masaüstü kısayolu, installer, kurulu hizmet ve GitHub değişmedi. Masaüstünde hedeflenen Ultron kısayolu sorgusu eşleşme vermedi; kısayol senkronize edildi denmez.

- App EXE UTC: `2026-10-04T18:15:21.6223922Z`, SHA-256: `6B1E9F1F720245D2D7DC2D360721242EDFB18D1061507FE63B7F0B78CAFF7661`.
- App DLL SHA-256: `85C492999BC222DC72DDA11DC4025509E2A4AA79905A951729C614EA52F42FD8`.
- Service DLL SHA-256: `F0B780ED2B31B0EC0E53D288BA2B2B23499D8C729A37D9F30CAAA1A41A44B09C`.

AI ayarını hizmette değiştirmek için güncel ve kimliği doğrulanmış hizmet gerekir. Ayrı EXE klasörü hazırlamak hizmet kurulduğu anlamına gelmez. Sonraki adım: mevcut hizmet yokluğunu kontrollü kurulum/VM pilotuyla ele alma; yeni uygulamayla başarısız tarama raporu ve tanılama correlation kodunu alma. Guardian kasa devri/çok kullanıcı/otomatik müdahale kapıları ayrı kalır.

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: başarısız taramanın gerçek runtime istisnası kaydedilmedi; kurulu UI'da fare davranışı ve hizmetin SYSTEM↔çok kullanıcı akışı canlı sınanmadı. Kaynak testlerinin geçmesi, bu bilgisayarda gerçek zamanlı korumanın çalıştığı veya ürünün birincil antivirüs olduğu anlamına gelmez.
