# 3.2.1 işlev incelemesi — 2026-09-27

## Doğrulanan düzeltmeler

- Zamanlayıcı/Raporlar yalnız metin sekmeleriydi: gerçek gezinme ve ortak zamanlama ayarları bağlandı. Session0 masaüstü bilgisi bilinmiyorsa kullanıcı tarafından açılan saatli tarama Low modda çalışabilir; AFK taraması hâlâ güvenli biçimde ertelenir.
- Servis/UI istisna listeleri ayrı bellekte eskimişti. Atomik yeniden yükleme, duplicate silme, detached snapshot, strict SHA-256 ve politika cache epoch eklendi. Dosya istisnası içeriğe bağlı; klasör istisnası açık uyarı ister. IPC gönderimi uygulandığına dair ACK değildir; admin/SYSTEM yetki sınırı korunur.
- Yerel rapor geçmişi 50 kayıt/4 MiB ile sınırlı ve atomik JSON'dur. Gerçek ScanResult snapshot'ı, iptal/hata/kısmi kapsam ve açıkça doğrulanan eylem kullanılır. Risk puanı veya olay kapatma tek başına karantina sayılmaz. Servis-geneli rapor deposu değildir.
- Ekrandaki CPU/RAM çakışması giderildi. CPU artık süreç CPU zamanının monotonic zaman ve mantıksal işlemci sayısına bölünmesiyle ölçülür; RAM managed heap değil gerçek working set'tir. İlk CPU örneği yoksa ölçülüyor görünür. Sahte yüzde-temelli aşama onayları kaldırıldı.
- Nominal 16 GB bilgisayarın donanım rezervi yüzünden High Auto eşiğinin altında kalması düzeltildi. RAM bütçesi yine gerçek fiziksel/boş RAM'den hesaplanır. Boş Quick/Full hedefi sistem diskine normalize edilir; tarama başında basınç yenilenir. RAM'i hedef yüzdeye doldurmak veya CPU'yu yapay yüklemek yapılmaz.
- Süreç sonlandırma PID adı yerine seçilen PID/başlangıç zamanı/gerçek görüntü yolunu aynı handle üzerinde doğrular. Kritik/öz süreçler ve belirsiz kimlik reddedilir; erişim reddi/PPL korunur. Canlı kullanıcı süreci sonlandırılarak test edilmedi; çekirdek yetkisi kazanıldığı iddia edilmez.
- ZIP/JAR iç dosyaları bounded, bellekiçi hash/pattern/YARA analizine bağlandı; aynı ortak hub gerçek zamanlı hatta da kullanılır. İsim değiştirilmiş ZIP de içerikten tanınır. Generic YARA kesin zararlı değildir; nested/büyük/desteklenmeyen öğeler kısmi kapsamdır. Aynı arşiv sonucu normal hatta yeniden kullanılır; dosyalar diske çıkarılmaz.
- Splash görünür minimumu 2.6 s, kapanış 350 ms; minimized başlangıç splash açmaz.
- 3.2.1 Inno paketi gerçek repo adresi, Windows minimumu, portable staging ve standart kaldırıcı kullanır. Toplu isimle taskkill ve tüm uygulama dizinini silme kaldırıldı; kayıtlı paket dosyaları dışındaki kullanıcı verisi korunur. Sürücü kurmaz. Build varsayılan masaüstünü veya çalışan servisi değiştirmez.

## Test kanıtı

`TestResults/WorkflowReview/workflow-release-verified.trx`: **335/335 Release** seçili test geçti; bunlar karma güvenlik birimi, benign disk/bileşen entegrasyonu, UI/viewmodel sözleşmesi, kaynak/altyapı ve performans testleridir; 335 gerçek-malware/OS-kernel testi değildir. Yeni dilim: UI18, rapor8, istisna/zamanlayıcı12, süreç/JAR17, kaynak10, hash-öncelik3, installer4. Önceki263'e72 vaka eklendi. Yeni dilimde beş inert disk/içerik karar testi gerçek motoru kullanır; canlı malware yoktur.

RED: UI9 hata; istisna/zamanlayıcı10 vakada6 hata; süreç/JAR15 vakada10 hata; shared JAR hub2 hata; kaynak10 vakada9 hata; hash-öncelik3 hata; installer4 hata. Derleme engelleri test başarısı sayılmadı. `Golden01` fiziksel EICAR ve iki eski STA/lifecycle grubu hariçtir. Önceki ana test DLL Defender tespiti atlatılmadı; bu koşu açık benign kaynak listeli Review projesidir.

Win11,12 logical CPU,~15.9 GiB RAM,80×16 KiB inert dosya mikro ölçümü:

| Mod | Önce ms / worker | Sonra ms / worker | Sonra test-host CPU ms / RSS MiB |
| --- | --- | --- | --- |
| VeryLow | 2110 / 1 | 2038 / 1 | 1859 / 152.4 |
| Balanced | 356 / 24 | 262 / 24 | 1812 / 180.8 |
| Auto | 418 / 24 | 277 / 36 | 1750 / 182.1 |
| Maximum | 343 / 48 | 263 / 48 | 1891 / 188.3 |

Önce `workflow-performance-before-x64.trx`, sonra `workflow-release-verified.trx`. Tek seri, küçük sıcak-cache/sıra etkili mikro ölçümdür; genel hızlanma oranı veya düşük cihaz sertifikası çıkarılmaz. RSS son örnektir, peak değildir; tüm test hostunu içerir. Advisory bütçe process hard-limit değildir. Tekrarda80 content-verified cache hit;7–58ms.

## Araştırma ve gerçek sınırlar

Son paket kanıtı: App/Service/Helper self-contained win-x64 publish; Review Release build **0 uyarı/0 hata**, installer kaynak sözleşmeleri **7/7**. Inno Setup compile exit0, paket `artifacts/release-3.2.1/UltronDefenderSetup.exe`,123351050byte; SHA256 `91D3641CFED48D36F5A3F6497ED79D67BB5F5E3CF7660C45D442491F85FFEB5D`, Authenticode `NotSigned`. App DLL SHA256 `0F592958FA9804ED791FEF6A836847E6C2F20595234075DE54D2A48309AFCDB1`; Service DLL `E3B0A8896B38361920196348F078BDEBEA90A161202FAE738E37FB74ED335F88`. Paket çalıştırılmadı; kurulu eski dosyalar/masaüstü/servis değiştirilmedi.

Modern .NET8 Windows7 desteklemez; tek bir ayarla bu bağımlılıklar taşınamaz. Windows10 sürüm/edition/ESU koşulları ayrıdır; antivirüs OS yamalarının yerini alamaz. [Microsoft .NET Windows desteği](https://learn.microsoft.com/en-us/dotnet/core/install/windows), [Windows10 ESU](https://www.microsoft.com/en-us/windows/extended-security-updates).

Kernel dağıtımı gerçek imzalama, uygun sürücü teslimi, HVCI/Secure Boot ve Windows VM testleri ister. Burada sürücü yüklenmedi veya testsigning açılmadı. [Microsoft sürücü imzalama](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing). Seçili process exit bütün alt süreçlerin çıktığını kanıtlamaz. [Process.Kill sözleşmesi](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.kill).

Defender false positive için doğru yol imzalama/şeffaf paket ve Microsoft'a inceleme gönderimidir; imza temiz tespit garantisi değildir. Defender kapatılmadı, istisna eklenmedi, dosya dış incelemeye gönderilmedi. [Microsoft FP/FN süreci](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-false-positives-negatives). Bu paket imzasız önizlemedir.

Minecraft/mod için JAR üye taraması bir gerçek kapsam iyileştirmesidir; encrypted/remote/multistage payload ve bilinmeyen zararlı garantisi yoktur. [CurseForge tarihsel 2023 olay raporu](https://blog.curseforge.com/safeguarding-our-community-curseforge-fighting-malware-incident-report/). Olayın bugünkü aktif kampanya olduğu iddia edilmez; IOC veya malware indirilmedi.

## Sonraki öncelik ve Şüphecilik ve Doğrulama Notu

P0: servis tek quarantine owner, kullanıcıya bağlı authenticated IPC/elevation ve writable self-root güven sınırı; kaynak kökeni doğrulanan imza kütüğü. P1: açık masaüstü AFK ajanı ve Win10 düşük-RAM/HDD/SSD/iş-laptop pilotu. P2: imzalı driver/installer, Defender submission ve yasal izolasyonlu malware/benign corpus değerlendirmesi.

Şu an tam doğrulayamadığım noktalar: gerçek kurulum→SYSTEM servis→UI→karantina uçtan uca, native kernel/pre-execution koruması, Defender'ın yeni paketi temiz görmesi, Windows10/7 cihaz matrisi ve gerçek WPF görsel etkileşim. Installer derlemesi kurulumun başarılı olduğunu kanıtlamaz. Üretime hazır veya Defender'dan daha iyi olduğu iddia edilmez.
