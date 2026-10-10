# 10 Ekim 2026 — son preview denetimi

3.2.4-preview.20261010 kod denetimi ve sınırlı preview teslimidir. Bu rapor malware etkinliği, kararlı sürüm veya tamamlanmış VirtualBox testi iddiası değildir.

## Yeni bulgular

Servis önbelleğinde kuyruk boşalması commit yerine kullanılıyordu; içerik hash alias'ı invalidation sonrasında kalabiliyordu. Clear/invalidation, daha önce kuyruğa alınmış yazımlarla aynı sıradan geçmiyordu. Çağıranın değiştirilebilir model referansı L1'de tutuluyordu ve iptal edilmiş bir lookup L1 hit dönebiliyordu. SQLite ACL'si normal kullanıcı oluşturucunun yazma yetkisini kaldırıyor; geçmiş anahtarı yalnız klasör olduğundan farklı tarama türleri çakışabiliyordu.

Sınırlı FIFO kanal ve gerçek commit bariyeri eklendi. Invalidation/clear aynı sıradan geçer; generation/pending guard eski SQL sonucunun yeniden L1'e alınmasını önler. Hatalı persist işlemi cache kararını devre dışı bırakır ve flush başarı gibi bildirilmez. Modelin değiştirilebilir alanları bağımsız kopyalanır. ACL yalnız mevcut oluşturucunun SID'sine write ekler; başka kullanıcılara write verilmez. HistoryV2 (root,type) anahtarına geçer; eski tablo silinmez ve son bilinen kayıt taşınır.

## Doğrulama kapsamı

Önceki değişmez 9 Ekim adayının 580 seçili benign regresyonu yeniden geçti (0 fail/skip). İlk yeni yedi DB fixture'ında altı başarısızlık görüldü; biri SQLite yazma hakkı nedeniyle kurulum aşamasındaydı, davranış assertion'ı değildi. Düzeltme sonrası yedi vaka geçti. Genişletilmiş yeniden açılış testi UTC dönüşümünü yakaladı; RoundtripKind/InvariantCulture ve expiry kontrolü eklendi. İlk 638-test turunda installer fallback sürümü uyuşmazlığı da bulundu ve giderildi. Son aday **654 passed / 0 failed / 0 skipped**; 16 mevcut imzalı-update fixture'ı fake HTTP/ephemeral key ve izole hedef kullanımı incelendikten sonra pozitif listeye dahil edildi. Başka işlemin bu test dosyası değiştirilmedi.

Bu seçki 12 yeni cache altyapı vakası ile diğer karar/sentetik kanıt, benign disk/ZIP, tarayıcı metadata ve off-screen WPF kontrollerini kapsar. Tüm main/lab paketinin günlük PC'de çalıştırıldığı veya geçtiği iddia edilmez. Çözüm Release derlemesi 0 hata/0 uyarı; son paket derlemesi ve uzak CI çıktıları ayrı teslim kanıtıdır. CI stacked PR ve final-audit branch yollarına da açılmıştır.

GitHub'ın ilk temiz ortam koşusu (run 38027684139) solution derlemesini 0 hata/uyarıyla tamamladı, fakat bağımsız Review projesinde NETSDK1004 ile durdu: solution restore bu ayrı projenin assets dosyasını üretmiyordu. Yerel obj dosyaları bu boşluğu gizlemişti. Önce eklenen restore-sırası regresyonu başarısız oldu; workflow'a explicit Review restore ve exit-code kontrolleri eklendikten sonra son yerel aday **655 passed / 0 failed / 0 skipped** verdi. Bu bir ek altyapı testidir; ilk 654'e yeniden koşu sayıları eklenmemiştir. Uzak CI yeniden koşusunun sonucu, installer hash'i ve yayın bağlantısı release teslim kaydında ayrıca belirtilir.

Queue, clear/invalidation ve gerçek SQL commit tek sıradan geçer. Pending invalidation/generation, eşzamanlı L2 okumayı miss'e dönüştürür. Dosya erişim hakları fixture üzerinde ve mevcut kullanıcı kimliğinde sınanmıştır; iki kullanıcı/SYSTEM native servis izolasyonu VM kapısıdır. Preview setup servis payload'unu içerir fakat onu kurmaz veya başlatmaz.

## Dar performans ve geri dönüş ölçümü

Aynı 5.000 submit + 5.000 L1 hit iş yükü: her aday için beş ayrı süreç, her süreçte ilk geçiş + beş sıcak geçiş. SQLite yazarı bilerek bloklandı; gerçek dosya/disk cold-cache ve tarama kuyruk gecikmesi ölçümü değildir. Sıcak medyan süre 59,94 → 69,10 ms (+%15,3); CPU medyanı her ikisinde 62,5 ms; süreç tepe belleği 61,17 → 61,17 MB (ondalık). İlk geçiş medyanı 66,10 → 75,05 ms; tepe bellek 52,60 → 54,81 MB. Kopyalama/sıralama korumasının maliyeti incelendi; sıradan verdict için kullanılmayan completion tahsisi kaldırıldı. Bu dar stres testindeki ~9 ms ek maliyet, değiştirilebilir karar referansını geri açarak giderilmedi. Tam tarama performans kapısının geçtiği veya hızlandığı iddia edilmez; gerçek eş kapsamlı korpus ölçümü hâlâ bekliyor.

Aktarım/geri dönüş inert fixture'ları yeniden geçti: kilit ve sonradan değişiklik ilk yazımdan önce ret; orijinal içerik ve tarih; idempotent geri dönüş; yeni dosyanın recoverable taşınması; zorlanan aktarım-ortası I/O hatasında otomatik eskiye dönüş; kullanıcı ve servis sentinel'leri korunur. Bu bir native installer/VM testi değildir. Paketler kaynak commit kimliğini açıkça alabilir; ilgisiz çalışma ağacı commit'i ürün sürümüne yazılmak zorunda değildir.

Canlı malware, crack siteleri ve günlük bilgisayardaki OS-mutating testler kullanılmadı. Servis, Defender, sürücü, firewall ve boot ayarları değiştirilmedi. Test toplamları malware yakalama oranı veya gerçek oyun korpusu false-positive oranı değildir.

## VirtualBox'a geçmeden önce

Yeni setup ayrı per-user preview kimliğindedir; servis/driver/autostart kurmaz veya uygulamayı başlatmaz. Microsoft Defender açık kalmalıdır. Snapshot alınmış izole Windows 10/11 x64 VM'de önce zararsız kurulum, light/dark hover/DPI, Quick/Full/Custom tarama, duraklat/iptal, bozuk/bütçeli arşiv, kaldırma ve geri dönüş doğrulanmalıdır. İmzalanmamış preview'ı günlük koruma yerine kullanmayın.

Gerçek ≥30 resmî benign dosya / altı aile / holdout, eş kapsamlı beş soğuk-beş sıcak baseline karşılaştırması, tüm contained PE adaptörlerinin eşitliği, yerel servis ve sürücü doğrulaması, trusted feed key ve imzalama hâlâ ayrı kapılardır.

## Yayın teslim kanıtı

[3.2.4 preview setup ve checksum](https://github.com/EmircanKurt/UltronDefender-Security/releases/tag/v3.2.4-preview.20261010) yayımlandı. Kaynak/tag `b2f10a927147eb9250b844ce1428bf80e777c235`; 1.037 public kaynak blob hash'i doğrulandı. [GitHub temiz CI run 38028063016](https://github.com/EmircanKurt/UltronDefender-Security/actions/runs/38028063016): 655 passed / 0 failed / 0 skipped, iki Release derlemesinde 0 warning / 0 error.

Setup Authenticode NotSigned; 126.091.934 bayt; SHA-256 `9F136FB11BEA70852EBC1E247BA006188DD0A46D6C82134EA552693082BAA480`. GitHub'dan setup ve SHA256SUMS tekrar indirildi ve mühürlenmiş paketle eşleşti. Setup çalıştırılmadı. Yerel portable uygulamanın 545 dosyası yedekli aktarıldı, 436 servis/helper ikilisi korundu; bu native servis veya installer doğrulaması değildir. Kod PR12'de ayrı kalır; main'e runtime değişiklikleri otomatik birleştirilmedi.

Şüphecilik ve Doğrulama Notu: Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: bu gerçek korpus, canlı input/DPI, VM ve native koruma kapıları tamamlanmadı. İnceleme tüm olası bug'ların bulunacağını garanti etmez.