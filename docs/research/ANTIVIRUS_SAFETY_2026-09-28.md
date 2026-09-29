# Ultron Defender — güvenlik sınırı düzeltmeleri (28 Eylül 2026)

Bu çalışma ürünün zararlı yakalama oranını ölçmez ve kurulu birincil antivirüsün güvenilirliğini kanıtlamaz. Önceki incelemede bulunan yanlış-pozitif ve yanlış-müdahale yolları, zararsız geçici dosyalar ile sahte servis yanıtları kullanılarak yeniden üretildi.

## Doğrulanan kök nedenler ve dar düzeltmeler

| Alan | Eski davranış | Bu çalışma |
| --- | --- | --- |
| Başlangıç taraması | `RiskScore >= 70` veya `BlockAndQuarantine` önerisi tek başına karantina ve ilişkilendirilen PID için süreç sonlandırma başlatabiliyordu. | Otomatik işlem yalnız `ConfirmedMalicious`, blok politikası, 64 haneli SHA-256, halen aynı dosya içeriği, kullanıcı izni/eşiği ve hash-bağlı kasa birlikte varsa denenir. Başlangıç dosya taramasından PID sonlandırma kaldırıldı. |
| Başlangıç sonucu/önbelleği | `Unknown` sonuç temiz sayılıyor; temiz önbellek yalnız boyut/zaman damgasına bakıyordu. | Tamamlanmamış inceleme ayrı sayılır ve tarama `Failed` olur; temiz önbellek yeniden SHA-256 eşleşmesi olmadan kullanılmaz. Puan tek başına kesin zararlı seviyesine yükseltilmez. |
| Kendi dizinleri | Uygulama/ProgramData/AppData kökü altındaki her dosya, içeriğe bakılmadan tarama kuyruğundan ve gerçek zamanlı incelemeden çıkarılıyordu. | Tarama yolundaki klasör tabanlı muafiyet kaldırıldı. Ürün durumu için yıkıcı-eylem koruması ayrı kaldı; bu yol üyeliği bir dosyanın güvenli olduğunu kanıtlamaz. |
| YARA | Kural adında `EICAR` geçmesi veya `confidence=absolute` metadatası kesin kanıta dönüştürülebiliyordu. | Yalnız tam, en fazla 128 baytlık canonical test içeriği bağımsız olarak doğrulanırsa mutlak kanıt verilir. Genel eşleşme sezgiseldir; gerçekten metin olan kısa dokümantasyon referansları düşük puan alır. |
| Bulut itibarı | MalwareBazaar sorgusu `Auth-Key` olmadan gönderiliyor; bozuk/eksik API yanıtı yanlış öğrenmeye yol açabiliyordu. | Opt-in, ayarlardaki geçerli istek-başı `Auth-Key`, tam SHA-256, yerel imzanın önceliği, en fazla 1 MiB yanıt ve başarısızlıkta `Unknown` uygulanır. Büyük/bozuk yanıt önbelleğe veya imza veritabanına yazılmaz. |
| Kernel IPC kararı | Yol/isim veya yüksek sezgisel puan, pre-op blok/bağsız karantina kararını tetikleyebiliyordu. | Blok için tamamlanmış kesin statik kanıt ve o anki dosyanın SHA-256 doğrulaması istenir. Pre-op karantina yapılmaz; zaman aşımı veya doğrulama hatası fail-open kalır. Bu bir derleme/benign test doğrulamasıdır, gerçek kernel sürücüsü etkinliği kanıtı değildir. |
| Davranış/fidye koruması | Süreç adının veya genel dizin önekinin güvenilir sayılması yanlış atlamalara yol açabiliyordu; yalnız `Temp` konumu yüksek güvene çıkabiliyordu. | Varsayılan uygulama-adı muafiyetleri kaldırıldı; kullanıcı izin listesi tam kanonik yolla karşılaştırılır, PID öz-koruması saklanır, korunan dizin sınırı segment bazlıdır. Tek başına `Temp` kesinlik sayılmaz. |
| Arayüz tehdit özeti | Tamamlanmamış/şüpheli başlangıç incelemesi temiz görünümü ve tekrar eden bulgu listesi üretebiliyordu. | Bilinmeyen sonuç ayrı gösterilir; yeni süpürmede eski bulgu listesi temizlenir ve sonuçla uzlaştırılır. Canlı kurulu arayüz gözlemi yapılmadı. |

MalwareBazaar'ın [resmî API belgesi](https://bazaar.abuse.ch/api/) her etkileşimde `Auth-Key` başlığını şart koşuyor. Bu testlerde gerçek anahtar veya canlı sorgu kullanılmadı.

## Bu oturumun doğrulama kanıtı

- Seçilmiş zararsız Release regresyon seti: **474/474 geçti**, 0 başarısız (`TestResults/AntivirusSafety/security-final-release.trx`). Bu karma birim/smoke kümesidir; tespit oranı veya canlı koruma kanıtı değildir. Ana test projesindeki fiziksel EICAR ve sistem üzerinde yan etki üreten senaryolar çalıştırılmadı.
- Review test projesi Release `--warnaserror` derlemesi: **0 uyarı, 0 hata**. Ayrı App/Service/Helper yayın ve Inno Setup derlemesi de tamamlandı; kurulum çalıştırılmadı.
- İzole paket: `artifacts/antivirus-safety-2026-09-28/UltronDefenderSetup.exe`; **123.354.684 bayt**; SHA-256 **`AB8AB005D15D460EA6FA856DC74C08E478D525B2212C1FDC5834528ACB736E96`**; Authenticode durumu **`NotSigned`**. Bu kimlik yalnız üretilen dosyayı tanımlar, güvenlik/tespit etkinliğini onaylamaz.
- Mevcut kurulu uygulama, servis, masaüstü kısayolu, Defender ayarları ve kullanıcı karantinası değiştirilmedi. Bu yeni düzeltmeler GitHub'daki önceki taslak PR'a henüz gönderilmedi.

## Kalan ciddi sınırlar

- **Windows 7 desteklenmiyor:** App ve servis `net8.0-windows` hedefli. Microsoft'un [.NET Windows destek matrisi](https://learn.microsoft.com/dotnet/core/install/windows) .NET 8 için Windows 7/8.1 desteği göstermiyor. Self-contained paket bunu değiştirmez. Windows 10 desteği de sürüm/edisyon bazında doğrulanmalı. Windows 7 için ayrı, desteklenen teknoloji/ürün stratejisi gerekir; bu çalışma geriye uyumluluk iddiasında bulunmaz.
- Kullanıcı tarafından yazılabilen ürün veri kökleri artık taranır, ancak geniş ürün-durumu koruması otomatik karantinayı bu alanlarda sınırlayabilir. Tam çözüm, ACL/kimlik/manifest doğrulaması ve ayrı kasa güvenlik sınırı gerektirir.
- Mini-YARA sınırlı dil ve ilk 16 MiB kapsamıyla çalışır. Kısa, geçerli metin olarak görünen zararlı betik düşük puan alabilir; bu değişiklik geniş tehdit korpusu veya sahte-pozitif ölçümü değildir.
- Kernel pre-op doğrulaması büyük dosyalarda bütçeyi aşabilir ve fail-open olur; gerçek imzalı sürücü, Windows 10/11 laboratuvarı, yük/latans ve hata enjeksiyonu testi yapılmadı.
- Kurulum paketi imzalı değildir. Microsoft Defender'ın paketi yanlış işaretlemeyeceği ya da ürünün Windows Defender'dan daha çok tehdit yakalayacağı gösterilmedi.
- Eski ana test projesindeki bazı EICAR/fiziksel sisteme dokunan senaryolar güvenli seçili test paketinin dışında. Test sayısı tespit oranı veya gerçek dünyadaki koruma seviyesini temsil etmez.

## Devam için kanıt temelli sıra

1. Yeşil zararsız regresyonlar ve Release uyarıyı-hata-sayan derleme CI'da korunmalı; imzasız izole paket yalnız laboratuvar denemesi olarak ele alınmalı. Kurulu uygulama/servis otomatik değiştirilmemeli.
2. Windows 10/11 sanal makine matrisinde sürücü yükleme, servis-UI IPC, scheduler, istisna ve kasa geri yükleme uçtan uca ölçülmeli; Windows 7 için ayrı teknik karar verilmeli.
3. [AMTSO'nun EICAR test dosyası değerlendirmesinde](https://www.amtso.org/wp-content/uploads/2018/05/AMTSO-Use-and-Misuse-of-Test-Files-in-Anti-Malware-Testing-FINAL.pdf) açıkladığı gibi güvenli testlerin yalnız sınırlı entegrasyon sinyali verdiği kabul edilerek bağımsız yanlış-pozitif korpusu, arşiv/oyun modu örnekleri ve kötü amaçlı yazılım laboratuvarı prosedürü hazırlanmalı. Gerçek örnekler günlük geliştirme makinesine konmamalı.
4. Düşük/orta/yüksek donanımda dosya sayısı, byte/s, CPU, RAM, disk gecikmesi, soğuk/sıcak önbellek ve AFK tarama etkisi ölçülmeli. Sadece CPU kullanımının artması başarı metriği değildir.

Şüphecilik ve Doğrulama Notu: Bu kodun kurulu uygulama ve gerçek imzalı kernel sürücüsüyle canlı sistemde aynı davranışı gösterip göstermediği doğrulanmadı. Ayrıca gerçek zararlı örnekleri, canlı bulut anahtarı, düşük donanım performansı ve Defender algısı test edilmedi; `474/474` bu boşlukları kapatmaz.
