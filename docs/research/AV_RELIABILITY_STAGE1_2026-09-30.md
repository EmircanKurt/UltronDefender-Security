# Ultron Defender güvenilirlik planı — ilk uygulama dilimi (2026-09-30)

Bu belge bir yayın onayı değildir. Hedef, Defender'ın yanında çalışan ek koruma için yanlış güvenlik kararlarını azaltmak ve kalan eksikleri ölçülebilir hâle getirmektir. Kurulu servis, gerçek kullanıcı kasası, Defender ayarları ve okul/iş bilgisayarları değiştirilmedi.

## Kodlanan ve doğrulanan dar alanlar

| Alan | Uygulama | Yerel kanıt / sınır |
| --- | --- | --- |
| Manuel Quick/Full | Tarayıcı, ana ekran ve tepsi aynı kaynak seçim/başlatma akışına girer. Hatırlanan manuel profil zamanlanmış tarama profilinden ayrıldı; eski tercih yüklemede bir kez taşınır. Kaynak modu ancak tarama koordinatöründe oturum sahiplenilince uygulanır. | Sahiplik ve ayar regresyonları geçti. Native WPF diyalog/tepsi pilotu yapılmadı. |
| Başlangıç süpürmesi yarışı | Dış tarayıcı kaydı atomik ve lease'e bağlı; manuel tarama sırasında Busy döner, geç gelen ilerleme/tamamlama yeni oturumu ezmez. İkinci süpürme ilk süpürmenin iptal belirtecini değiştirmez. | Benign eşzamanlılık testleri geçti. Canlı servis/arayüz uzun süreli yarışı ölçülmedi. |
| Kasa risk etiketi | Açıklama metni veya istemci kanıtı kesinlik üretmez. Fiilen kasaya alınan içeriğin SHA-256 değeri yalnız uygulamayla gömülü imza kümesinde eşleşirse `ConfirmedMalicious`; aksi hâlde `Unknown`. Değiştirilebilir disk imzaları bu kesinlik yolunun dışında. | Benign ve sahte kanıt negatifleri ile gömülü-hash sınıflandırma birim testi geçti. Bu bir zararlı yakalama oranı değildir. |
| Eski kasa metaverisi | Kanıtsız eski risk etiketleri açılışta yalnız görüntülemede `Unknown` olur; veritabanı otomatik değiştirilmez. Ayrı bakım çağrısı önce SQLite snapshot ve `integrity_check`, ardından yedekteki en yüksek ID'ye kadar `Unknown` geçişi ve tek-seferlik işaret uygular. Mevcut kasa anahtarı açılmıyorsa motor geçişten önce durur. | Yalnız geçici kasa testleri geçti; gerçek çok kullanıcılı SYSTEM↔arayüz geçişi ve geri dönüş tatbikatı yapılmadı. |
| IPC durum doğruluğu | `GetStatus` yanıtı isteğin `RequestId` değeriyle eşleşmeden taze durum sayılmaz; kopuş ve beş saniye zaman aşımı hata verir. | Geçici named-pipe altyapı testleri geçti. Eski kurulu servis ID yansıtmayacağı için yeni arayüzle eşzamanlı sürüm geçişi gereklidir. Bu değişiklik kasa yetkilendirmesi sağlamaz. |
| İç içe ZIP/JAR | Bir alt seviye, 8 arşiv / 256 üye / 32 MiB bütçesiyle incelenir. Daha derin, şifreli veya limit dışı içerik tam temiz sayılmaz; kısmi bulgu kanıtı korunur ve temiz cache'e yazılmaz. Dosya adı tek başına arşiv kararı değildir. | Beş zararsız arşiv regresyonu geçti. Geniş gerçek oyun-modu ve yanlış-pozitif korpusu yok. |
| Ölçüm | Başlangıç kontrolleri/dosya kuyruğu ayrı süre logları, etkin işçi/kota/bekleyen sayıları ve tarama boyunca örneklenen tepe süreç working set değeri var. Etkisiz `MaxScanConcurrency` yapılandırma anahtarı kaldırıldı; eski JSON anahtarı zararsızca yok sayılır. | Bu metrikler hız artışı veya kesin anlık RAM tepe değeri değildir. Disk başına p95, MB/s ve beş tekrarlı cihaz matrisi henüz yok. |

## Yerel doğrulama

- `dotnet build AegisPC.sln -c Release --no-restore --warnaserror`: 0 uyarı, 0 hata.
- Güvenli ve açık kaynak listeli Review paketinde 513/513 seçili karma regresyon geçti (`TestResults/AVPlan/av-plan-stage1-final.trx`). Bu toplam altyapı, güvenlik birimi ve bazı geçici-disk entegrasyon testlerini karıştırır; **513 zararlı örnek testi veya tespit başarısı değildir**. Gerçek zararlı, kurulu SYSTEM servisi, üretim kasası ve bazı OS/Defender duyarlı testler bu çalıştırmada yoktur.
- Uygulama ve servis ayrı `artifacts/av-plan-stage1/` altında framework-dependent Release olarak yayımlandı; kurulum/servis güncellemesi yapılmadı. Uygulama DLL SHA-256 `6AB80DD984D970B6D4132CCEECDA5BBB295EC9AC4B761283381FFBF7931590D7`; servis DLL SHA-256 `6F82D0BBE4A66C52C42678FA2D558A669F71141FEE8BEC956D98BA883B7A96C7`.
- `AegisPC_App/UltronDefender.exe` hâlâ 26.09.2026 tarihli eski taşınabilir sürüm; SHA-256 `76CDEBF40462A0556659209A75FAABC974741F79873BC4019A0C30A96CB1C5B8`. Masaüstü kısayolu veya kurulu ürün bu değişiklikleri kullanmıyor. Yeni paket imzalı kurulum olarak üretilmedi.

## Açık yayın kapıları

1. **P0:** Servis ortak kasanın tek sahibi değil. UI ve servis ayrı `QuarantineService` kuruyor; standart kullanıcı kayıt yetkisi, oturum kimliği, geri yükleme izinleri ve kontrollü kasa geçişi/geri dönüşü eksik. Bu yüzden eski kayıtları açılışta yalnız `Unknown` gösteriyoruz; fiziksel bakım geçişi kurulu kasada başlatılmadı. Çok kullanıcı VM testi ve offline geri dönüş tatbikatı geçmeden installer/primary AV yayını yok.
2. **Performans:** Tam tarama sabit sürücüleri tek tek geziyor ve tek başlangıç diski sınıflandırması kullanıyor. SSD/HDD başına adil sınırlı kuyruk, ortak CPU/bellek sınırı, disk bazlı p95/MB/s ve 2–4/8/16+ GB makine matrisi uygulanmadı. CPU/RAM kullanımını zorla yükseltmek hız kanıtı değildir. Varsayılan politika değişimi için aynı kapsamla en az beş tekrar ve planın %10/%5 eşikleri gerekir.
3. **Tespit ve RT:** Temiz okul/iş yazılımları ile oyun-modu yanlış-pozitif korpusu ve izole yetkili tespit korpusu yok. Olay kaybı/kör noktaların uçtan uca görünürlüğü, ön-erişim bloklayan imzalı minifilter ve geri alma testleri yok; Defender kapatılmamalı. [Microsoft minifilter açıklaması](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers), [istisna riski](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-overview).
4. **Platform/dağıtım:** İmzalı uygulama/kurulum, doğrulanmış güncelleme/kaldırma/geri dönüş pilotu yok. [Windows 7 fizibilite raporu](WINDOWS7_FEASIBILITY_2026-09-29.md) mevcut .NET 8 ürün için NO-GO; VM'de denenmedi ve sürüm vaadi verilmez. [Microsoft .NET Windows desteği](https://learn.microsoft.com/dotnet/core/install/windows). Windows 10'un normal desteği bitmiştir; bazı LTSC/ESU istisnaları vardır, bir AV OS açığını kapatmış sayılmaz. [Microsoft Windows yaşam döngüsü](https://learn.microsoft.com/en-us/lifecycle/faq/windows).

İzleyen işler bağımsız incelenebilir PR'lara ayrılmalı; bu kod ağacı canlı dağıtıma hazır diye etiketlenmemeli.

## Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: kurulu çok kullanıcılı kasanın erişim ve geri dönüş davranışı, düşük RAM/HDD'deki gerçek darboğaz, temiz/zararlı korpusta yanlış-alarm ve yakalama oranı, ve gerçek zamanlı olayların kaybı henüz ölçülmedi. Bu kanıtlar gelmeden Ultron Defender'ın Defender'ın yerini aldığı iddia edilmemelidir.
