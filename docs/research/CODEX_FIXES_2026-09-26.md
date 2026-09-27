# Uygulanan düzeltmeler ve doğrulama — 26 Eylül 2026

## Sonuç

Gemini sonrası incelemede bulunan kritik hatalara kod düzeltmeleri uygulandı. Mevcut çalışma ağacındaki diğer değişiklikler korunmuştur. Bu çalışma bir üretime uygunluk sertifikası değildir; aşağıdaki kalan işler tamamlanmadan okul ve iş bilgisayarlarına geniş dağıtım önerilmez.

## Karantina ve veri güvenliği

- Kaynak dosya, okuma ve silme yetkili aynı Windows dosya tanıtıcısıyla tutulur. Yazma ve dosyanın yerine başka bir dosya koyma, karantina işlemi bitene kadar engellenir. Silme dosya adına değil bu tanıtıcıya uygulanır.
- Açılan dosyanın gerçek yolu yeniden doğrulanır; son bileşendeki reparse point takip edilmez. Güvenli doğrulanamayan kaynakta işlem durur. Salt okunur dosyalar güncel Windows sürümlerinde yolun özellikleri değiştirilmeden kaldırılabilir.
- Yeni kayıtlar V4 kullanır: farklı türetilmiş şifreleme ve doğrulama anahtarlarıyla AES-CBC + HMAC-SHA256. Başlık ve şifreli içerik doğrulanmadan düz metin üretilmez. Bu yaklaşım Microsoft'un [CBC için encrypt-then-MAC önerisiyle](https://learn.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode) uyumludur. V1/V2/V3 okuma desteği korunmuştur; eski kayıtlar kendiliğinden V4'e dönüştürülmez.
- Kasa diske flush edilir, geri okunur, çözülür ve SHA-256 ile kaynakla karşılaştırılır. Kaynak ancak bundan ve SQLite kaydından sonra kaldırılır. Kaynak kaldırıldıktan sonraki bir bildirim hatası kurtarma kopyasını silemez.
- ID tahsisi SQLite işlemiyle kalıcıdır; farklı motor örneklerinin aynı ID'yi alması engellenir. JSON geçişindeki ID çakışmalarında kayıtlar atılmaz, yeni ID verilir. Özgün JSON yedeği korunur; geçiş işareti veritabanındadır.
- JSON uyumluluk aynası SQLite işleminden sonra başarısız olduğunda, onaylanmış kayıt boşa düşürülmez. Dizinle çakışan indeks yolu önceden reddedilir. İptal edilmiş çağrının token'ı geri alma işlemini engelleyemez; veritabanı telafisi başarısızsa kasa kopyası korunur.
- `entropy.dat`, `vault_entropy.dat`, eski sabit entropy ve iki DPAPI kapsamı okunabilir. Çözülemeyen mevcut anahtar değiştirilmez. Yeni anahtar/entropy dosyaları atomik ve kalıcı yazılır; oturumlar arası dosya kilidi eşzamanlı başlatmayı korur.
- Geri yükleme ve silme aynı süreç içinde kayıt başına kilitlenir. Geri yükleme izni başarılı işlemden sonra yalnız **yol + doğrulanmış SHA-256** için beş dakika verilir. Aynı yola farklı içerik konursa bu izin geçerli değildir.

Tanıtıcı üzerinden silme davranışı [Windows API belgesine](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle), reparse point açma davranışı [CreateFile belgesine](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) göre uygulanmıştır. Silme, diskteki eski sektörlerin güvenli fiziksel imhası garantisi değildir.

## Yanlış pozitifler ve eksik tarama

- Birkaç sezgisel sinyalin toplamı artık kesin virüs ve otomatik karantina kararına dönüşmez. Kesin imza kanıtı yoksa yüksek skor uyarı olarak kalır; kesin imza testleri karantinayı doğrulamaya devam eder.
- Microsoft imzası yalnız yol adı veya yayımlayıcı adındaki alt dizgeyle varsayılmaz.
- Dedektör hata sayısı dosya sonucunda taşınır. Hata, sıfır etkin dedektör veya bilinen kapsam sınırı, temiz sonuç olarak saklanmaz. Analiz tamamlanmamışsa normal dosya taraması başarısız/kısmi inceleme açıklaması verir; bundan bir virüs suçlaması üretilmez.
- Arşivlerde 25.000 üye, 500 MB açılmış boyut bütçesi, büyük gömülü dosya ve iç içe arşiv sınırları açıkça raporlanır. İptal yutulmaz. APK, ZIP tabanlı incelemeye dahil edilmiştir.
- Managed YARA'nın ilk 16 MB sınırı kaldırılmadı; artık bu sınırın arkasındaki içerik taranmış gibi raporlanmaz.

## Performans ve kaynak yönetimi

- Otomatik mod arayüzde Dengeli'ye çevrilmez; başlangıç penceresinde ayrı Otomatik seçeneği vardır.
- Ortak ScanContext gerçek analiz yoluna bağlanmıştır. Authenticode ve konum dedektörü aynı dosyanın imzasını paylaşır. Eşzamanlı bağlam tüketicileri hash/imza hesabını tekilleştirir.
- Normal ve arşiv sonuçlarında önceden hesaplanan SHA-256 önbelleğe geçirilir. Önbellek doğrulaması asenkron ve iptal edilebilir; içerik değişiminde hesaplanan yeni hash normal analizde tekrar kullanılır.
- Aynı boyut ve zaman damgası güvenlik kanıtı sayılmaz: içerik hash doğrulaması korunmuştur. Isınmış önbellekte büyük dosyanın tamamen okunması hâlâ gerekir.
- Kaynak yöneticisi gerçek tarama hedefinin disk politikasını alır. Bilinmeyen/ağ depolaması hızlı SSD varsayılmaz. HDD'de en fazla iki eşzamanlı dosya işçisi kullanılır.
- RAM üst bütçesi toplamın en fazla %60'ıdır. Bellek baskısı %88 veya üzerindeyse manuel Tam Güç dahi tek işçiye ve düşük bütçeye iner. Bu bir bütçedir; programın RAM'i dolduracağı veya belirli CPU yüzdesine ulaşacağı sözü değildir.
- Otomatik hız artışı üç kararlı örnek bekler; değişmeyen profil sürekli yeniden yayımlanmaz. İşçi bırakma/profil küçültme yarışı ve timer kapanış yarışı düzeltilmiştir. Kasa kapatılırken süreç genelinde zorunlu GC yapılmaz.

## Testler

- Son izole regresyon grubu: **134 başarılı, 0 başarısız, 0 atlanan**. Son çalıştırma yaklaşık 17 saniyedir; bu uygulamanın tarama hızı ölçümü değildir.
- Yeni test dosyalarında 29 test vakası vardır: kaynak değiştirme/yeniden adlandırma, iki motor, ID kalıcılığı, gerçek eski entropy ve DPAPI, çakışan eski kayıtlar, indeks hatası, eski kapsayıcı geri yükleme, altı farklı V4 kurcalama noktası, salt okunur kaynak, çoklu sezgisel sinyaller, dedektör hatası/eşzamanlılığı, sıfır dedektör, ortak imza bağlamı, kaynak profilleri, önbellek iptali/içerik değişimi ve arşiv sınırı/iptali.
- Kaynak profili testleri 1–32 çekirdek, 512 MB–64 GB RAM, HDD/SSD ve altı mod için 60 birleşimi denetler. Bu **fiziksel donanım benchmark'ı değildir**.
- Aynı içerikte farklı dosya yolları ayrı kurtarma kayıtları olmaya devam eder; yalnız aynı hash yüzünden ikinci dosya kaybolmaz.
- Rapor: `TestResults/ReviewFixes/review-fixes.trx`. DPAPI CurrentUser testleri kullanıcı profiline erişebilen ortamda çalıştırılmıştır.
- Bütün test paketi çalıştırılmadı. Gerçek masaüstü/sistem müdahalesi ve karışık STA arayüz testleri bu izole grupta yoktur. İki disk tabanlı YARA/EICAR entegrasyon vakası dış AV müdahalesi nedeniyle filtre dışıdır; bellek tabanlı YARA ve karar testleri gruptadır. Defender ayarları değiştirilmedi, gerçek zararlı indirilmedi.

## Dağıtım öncesi kalan işler

1. **Tek servis sahibi ve IPC:** UI'nın doğrudan kasa işletmesi kaldırılmalı; standart kullanıcı/servis hesaplarıyla ortak, kimliği doğrulanmış tarama ve karantina oturumu protokolü kurulmalı. Yeni anahtarlar hâlâ LocalMachine DPAPI kullanır; yetki ayrımı ve kasa ACL'leri bu mimariyle birlikte sertleştirilmeli. Süreçler arası geri yükleme/silme koordinasyonu da bu aşamadadır.
2. **Eski kurulum klasöründen geçiş:** Aynı kasadaki eski anahtar ve indeksler desteklenir; `%APPDATA%\AegisPC\QuarantineVault` ile yeni ProgramData kökü arasında otomatik, doğrulanmış ve yedekli klasör aktarımı henüz yoktur. Bu rapordaki anahtar testi bunun tamamlandığı anlamına gelmez.
3. **Çökme/güç kaybı günlüğü:** SQLite ve dosya sistemi tek atomik işlem değildir. Kesinti anı için kalıcı Pending/Committed durum günlüğü, kurtarma ve gerçek süreç çökmesi testleri gerekir. Başka motorun aktif staging dosyasını silebilecek başlangıç temizliği devre dışı bırakılmıştır; güvenli orphan uzlaştırması tamamlanmalıdır.
4. **Kademeli I/O–CPU hattı:** Gerçek disk başına I/O kapıları, NVMe ayrımı, disk gecikmesi/aktiflik ölçümü, CPU darboğazı tespiti ve buffer tahsis kotası henüz tamamlanmadı. RAM bütçesi bütün analiz katmanlarında sert tahsis sınırı değildir. CPU'yu yapay olarak yüksek tutmak hedef değildir; iş/saniye ve sistem yanıtı ölçülmelidir.
5. **Tam kapsamlı desen taraması:** Büyük dosyalarda bounded streaming veya doğrulanmış native YARA; büyük/iç içe arşivlerde kapsam ve kota politikasının genişletilmesi gerekir. Şu an bu işler temiz diye gizlenmez, fakat tam tarama da yapılmaz.
6. **Uyumluluk ve pilot:** Gerçek 2–4 GB RAM/HDD okul PC'si, standart kullanıcı iş laptopu/pil, SSD ve NVMe güçlü PC üzerinde soğuk/sıcak tarama, UI yanıtı, RSS, disk gecikmesi, dosya/saniye, iptal süresi ve yanlış pozitif oranı ölçülmeli. Cloud/reparse dosyaları, ağ yolları, alternatif veri akışları ve çok büyük dosyalar için ayrı test matrisi gerekir. .NET destek sürümü geçişi ve kurulum/güncelleme pilotu ayrıca tamamlanmalıdır.

Bu işler için gerçek kullanıcı kasası, Defender ayarları, okul/iş cihazları veya kurulu servis üzerinde bu çalışma sırasında değişiklik yapılmamıştır.
