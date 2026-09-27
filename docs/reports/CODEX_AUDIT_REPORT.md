# AegisPC — Bağımsız Faz 1 Denetim Raporu

Denetim tarihi: 2026-09-07  
Kapsam: çalışma ağacındaki mevcut kaynak; Faz 1 kapsamında uygulama kodu değiştirilmedi. Önceki düzeltme kaydı (`knowledge/history/bug_fixes.md`) karşılaştırıldı; aşağıdaki maddeler o kayıtta kapatılmış sorunların tekrarı değildir.

## Özet

| Şiddet | Adet |
|---|---:|
| 🔴 Kritik | 3 |
| 🟠 Yüksek | 5 |
| 🟡 Orta | 3 |
| 🟢 Düşük | 1 |

## Bulgular

### 🔴 AUD-01 — Ad/yol temelli muafiyetler saldırgan tarafından taklit edilebilir

**Kanıt:** `src/AegisPC.Core/Helpers/PathHelper.cs:46-65` yalnızca yol parçasında `steamapps`, `epic games` vb. geçmesine göre oyun dizini kararı verir. Bu sonuç `src/AegisPC.Security/Scanning/ScanFilterPolicy.cs:216-220`, `src/AegisPC.Security/Scanning/FileScannerService.cs:98` ve `src/AegisPC.Security/Scanning/ArchiveSafetyScanner.cs:52-55` içinde taramayı azaltmak/atlamak için kullanılır. Ayrıca `ScanFilterPolicy.cs:58-108` genel isimlerle (`AegisPC`, `bin`, `obj`, `Release`, `x64` vb.) dizin atlar; `DirectoryWalker.cs:126-128` da `AegisPC_` ve `AegisLabSuite_` ön eklerini atlar.

**Etkisi:** Zararlı bir dosya adını ya da yerleştiği klasörü örneğin `C:\\Users\\...\\steamapps\\common\\...`, `AegisPC_payload` veya `bin` yaparak tam/özel taramanın ilgili alt ağacından kaçabilir. Bu, önceki SEC-02/SEC-05 kayıtlarına rağmen halen güvenlik kararının ad/yol metnine dayanmasıdır.

**Öneri:** Genel ada dayalı oyun, geliştirme ve self-exclusion kurallarını kaldırın. Self exclusion yalnızca kanonikleştirilmiş gerçek kurulum kökü, sahiplik/ACL ve doğrulanmış uygulama imzası birlikte sağlanınca uygulanmalı; oyun dosyaları için de taramayı atlamak yerine kaynak sınırı uygulayın.

### 🔴 AUD-02 — `BrushSidebarHover` iki tanımsız dinamik kaynak olarak kullanılıyor

**Kanıt:** `src/AegisPC.App/Resources/Themes/Components.xaml:444` ve `:490`, `{DynamicResource BrushSidebarHover}` kullanıyor. Tüm uygulama XAML dosyalarındaki `x:Key` tanımlarıyla yapılan taramada bu anahtarın tanımı bulunmadı; `rg` taraması da yalnızca bu iki kullanımı döndürüyor. 

**Etkisi:** İlgili hover tetikleyicileri çalışırken kaynak çözümlenemiyor. İstek gereği, tanımsız herhangi bir static/dynamic tema kaynağı kritik kabul edilmiştir.

**Öneri:** Her iki tema sözlüğünde `BrushSidebarHover` tanımlayın veya mevcut, temaya uyumlu bir anahtara yönlendirin. Statik bütünlük testini DynamicResource referanslarını da doğrulayacak şekilde genişletin.

### 🔴 AUD-03 — Sınır denetimsiz güvenli-yol tanımı ve yayıncı adına göre hash atlama

**Kanıt:** `src/AegisPC.Core/Helpers/PathHelper.cs:10-15`, `StartsWith` ile `Windows`, `Program Files` ve `Downloads` güven kararını verir; dizin sınırı veya kanonik/reparse-point denetimi yoktur. `src/AegisPC.Security/Scanning/FileHashMatcher.cs:128-144`, bu sonuçla yola girip, geçerli imza sahibinin metninde `Microsoft`, `Windows` veya `Google` varsa hash ve sonraki analizi tamamen atlar. `FileScannerService.cs:132-136` bu bayrakta doğrudan `null` döndürür.

**Etkisi:** `C:\\WindowsEvil\\...` ve `C:\\Program Files Evil\\...` gibi önek çakışmaları güvenli yol sayılır. İmza sahibi metnine dayalı ve revocation kapalı doğrulama ile birleşince bir dosya, içerik/hash denetiminden önce temiz geçiş alabilir.

**Öneri:** `Path.GetFullPath` ardından kök-ayırıcı sınırı olan karşılaştırma ve reparse-point çözümü kullanın. Fast path yalnızca doğrulanmış Microsoft/WHQL kimliği, kanonik gerçek sistem kökü ve bilinen güvenli hash ile uygulanmalı; güvenilir yayıncı adı tek başına karar olmamalı.

### 🟠 AUD-04 — İçerik-over-extension ilkesi uygulanmıyor; büyük dosyalar mutlak atlanıyor

**Kanıt:** `src/AegisPC.Security/Scanning/ScanFilterPolicy.cs:210-214`, `.pdf`, `.jpg`, `.json`, `.db`, `.log`, `.config` vb. uzantılı dosyaları ilk baytları okumadan doğrudan dışarıda bırakıyor. Aynı sınıf `:226-230`, 100 MB üzerindeki bütün dosyaları dışarıda bırakıyor. `FileScannerService.cs:95` de 100 MB üzeri dosyayı `null` döndürüyor.

**Etkisi:** MZ/komut dosyası içeren `invoice.pdf` veya 100 MB üzeri PE/ISO/arşiv, aday taramaya hiç ulaşmaz. Bu hem koddaki “content-over-extension” açıklamasıyla çelişir hem de kolay bir kaçınma yoludur.

**Öneri:** Güvenli uzantılarda küçük bir magic-byte/shebang örneği okuyun; yürütülebilir içerik gördüğünüzde taramaya devam edin. Büyük dosyalarda tamamen atlamak yerine boyut-kotalı streaming hash, arşiv manifesti ve örnekleme ile “incelenemedi” telemetrisi üretin.

### 🟠 AUD-05 — Oyun/proxy sınıflandırması tek bir gömülü metinle risk azaltabiliyor

**Kanıt:** `src/AegisPC.Core/Helpers/GameCrackClassifier.cs:91-119`, MZ ile başlayan dosyanın ilk 64 KiB içinde `SteamAPI_Init`, `Direct3DCreate9` vb. tek bir dizge varsa `true` döndürüyor. `RiskScoringEngine.cs:60`, `:105`, `:155`, `:192` ve `:208-224` bu sonucu PUP, packer, imzasız ikili ve API göstergesi cezalarını atlamak/azaltmak için kullanıyor.

**Etkisi:** Bir saldırgan ilk 64 KiB’e tek oyun API dizgesi ekleyerek birden fazla risk sinyalini bastırabilir. Hash listesi bu yolu telafi etmez çünkü metin yolu ondan bağımsızdır.

**Öneri:** Bu boolean muafiyeti kaldırın. Proxy/export analizi kullanılacaksa PE export tablosunu yapısal olarak doğrulayın; şüpheli davranış, bilinen kötü hash ve içerik eşleşmelerinde hiçbir indirim vermeyin.

### 🟠 AUD-06 — Bilinen PUP hash’i imzalı/güvenli konumlu örnekte puanlanmıyor

**Kanıt:** `src/AegisPC.Security/Scanning/RiskScoringEngine.cs:79` hash’i hesaplar; fakat `:92-126` içindeki `isKnownPup` ile +50 verme bloğu yalnızca `!result.IsSigned && !result.IsKnownLocation` olduğunda çalışır. Buna karşılık `:65-76` imzalı/konumlu dosyadan puan düşer ve `:235-249` bazı imzalı/sistem dosyalarında skoru sıfırlar.

**Etkisi:** Aynı hash, imza/konum bayraklarıyla birlikte verildiğinde PUP eşiğine ulaşmayabilir. Bilinen kötü içerik, güven sinyalleriyle geçersiz kılınmamalıdır.

**Öneri:** Bilinen kötü/PUP hash için imza ve konumdan bağımsız, açık ve test edilmiş bir öncelik kuralı tanımlayın; ürün politikasına göre blok/uyarı eşiğini belirleyin.

### 🟠 AUD-07 — Uzun ömürlü koleksiyonlarda gerçek üst sınır yok

**Kanıt:** `RiskScoringEngine.cs:33-40` statik `DynamicPupHashes` için sınır/TTL yok. `StartupSecuritySweepService.cs:33` `_fileCache` için sınır/temizlik yok. `SecurityFindingService.cs:16,50` `_findings` listesine sadece ekliyor; `WebShieldService.cs:25-26` blok/bypass sözlükleri için de kapasite veya yaşlandırma yok. Buna karşılık `FileHashMatcher.cs:43-97` ve `SignatureVerifier.cs:20-194` üst sınır içeriyor; yani bu, önceki cache düzeltmelerinin tekrarı değil, kapsam dışı kalan koleksiyonlardır.

**Etkisi:** Sürekli tarama, güncelleme veya kullanıcı kuralı ekleme sürecinde bellek kullanımı zamanla büyür.

**Öneri:** Her koleksiyon için sahiplik gereksinimine uygun kapasite/TTL/LRU ve kalıcı depolama stratejisi belirleyin; güvenlik bulgularında sorgu/paginasyon kullanın.

### 🟠 AUD-08 — Sertifika doğrulaması iptal (revocation) durumunu kontrol etmiyor

**Kanıt:** `src/AegisPC.Security/Scanning/SignatureVerifier.cs:116-120`, `X509Chain` için `RevocationMode = NoCheck` ayarlar. `:219-226` WinVerifyTrust çağrısında da `WTD_REVOKE_NONE` ve `WTD_REVOCATION_CHECK_NONE` kullanılır.

**Etkisi:** Süresi içinde kalmış ancak iptal edilmiş sertifika güvenli kabul edilebilir; bu özellikle AUD-03 fast path’ini zayıflatır.

**Öneri:** Çevrimiçi doğrulama uygun değilse güvenilir bir zaman damgası/önbellek politikasını açıkça tasarlayın; normal çalışma modunda sertifika iptal kontrolünü etkinleştirin ve erişilemezlikte “güven doğrulanamadı” fail-closed/fail-warning kararını ürün politikasında belirtin.

### 🟡 AUD-09 — Tarama kritik yolları erişim hatalarını sessizce kaybediyor

**Kanıt:** `src/AegisPC.Security/Scanning/DirectoryWalker.cs:135,139,208,211,249`, `FileHashMatcher.cs:126`, `ScanFilterPolicy.cs:173` ve `ArchiveSafetyScanner.cs:190` boş `catch` blokları içeriyor. Örneğin `DirectoryWalker.cs:139` erişilemeyen dizini yutuyor ve kullanıcının ilerleme/sonuçlarına taranmayan yolu eklemiyor.

**Etkisi:** Tarama çökmese de kullanıcı “tamamlandı” sonucunu görürken kapsanmayan dosya/dizinleri bilemez; hata gözlemlenemez.

**Öneri:** Beklenen erişim istisnalarını sınırlı biçimde yakalayın, yapılandırılmış log ve “atlanan/erişilemeyen öğe sayısı” telemetrisi ekleyin. İptal istisnasını ayrı tutun.

### 🟡 AUD-10 — XAML testi DynamicResource’ları ve gerçek tema yükleme başarısızlığını doğrulamıyor

**Kanıt:** `tests/AegisPC.Tests/XamlStaticResourceIntegrityTests.cs:45-72` yalnızca `{StaticResource ...}` regex’i tarıyor. `:99-114`, sözlük yükleme hatalarını boş `catch` ile yutuyor; test sözlüğü ise uygulamanın başlangıçta yüklediği `Colors.Light.xaml` yerine `Colors.Dark.xaml` kullanıyor. Bu nedenle AUD-02 testten kaçmış, buna rağmen bu test 5.46 saniyede geçti.

**Etkisi:** “Tüm kaynaklar ve tüm View’lar render edildi” iddiası mevcut testin kanıtladığından daha geniştir.

**Öneri:** App.xaml’in gerçek merged-dictionary sırasını yükleyin, sözlük yükleme hatasını başarısız sayın, static+dynamic referanslarını doğrulayın ve STA iş parçacığının zaman aşımında halen yaşıyor olup olmadığını test başarısızlığı yapın.

### 🟡 AUD-11 — Büyük üretim sınıfları SRP/satır sınırını aşıyor

**Kanıt:** Bu denetimde ölçülen 400+ satırlık üretim dosyaları: `YaraEngine.cs` 609, `QuarantineService.cs` 523, `StartupSecuritySweepService.cs` 522, `MsrtRemediationEngine.cs` 508, `QuarantineViewModel.cs` 498, `PerformanceViewModel.cs` 494, `TransactionalQuarantineEngine.cs` 487, `DnsProtectionService.cs` 455, `DeepPeAnalyzer.cs` 454, `ThreatSignatureDatabase.cs` 439, `DashboardViewModel.cs` 429 ve `BehaviorEngine.cs` 410 satır. Bu ölçüm, önceki rapordaki eski monolit sayılarını tekrar etmez; mevcut çalışma ağacının sayımıdır.

**Etkisi:** `AI_GUIDELINES.md` 4.1/4.3’teki tek sorumluluk ve dosya sınırı ihlal ediliyor; özellikle YaraEngine/QuarantineService/StartupSecuritySweepService hem I/O, politika hem de durum yönetimi barındırıyor.

**Öneri:** Güvenlik davranışını değiştirmeden, onaylı ayrı bir mimari işte dosya başına sorumluluk ayrıştırması yapın.

### 🟢 AUD-12 — Cache FIFO kuyruğu aynı yol tekrar yazıldığında gereksiz büyüyebilir

**Kanıt:** `src/AegisPC.Security/Scanning/FileHashMatcher.cs:96-97` aynı `path` için sözlük girdisini güncellerken her seferinde `_cacheKeyQueue.Enqueue(path)` yapıyor. Tahliye yalnızca sözlük `MaxCacheEntries` sınırına geldiğinde (`:88-94`) çalışıyor; tek/az sayıda sıcak yol tekrar taranırsa sözlük küçük kalırken kuyruk büyür.

**Etkisi:** Uzun süren gerçek zamanlı izleme altında gereksiz bellek birikimi oluşabilir.

**Öneri:** Kuyrukta mevcut anahtarı tekrar eklemeyi önleyin veya kuyruk uzunluğunu sözlük kapasitesiyle sınırlandırın.

## Doğrulama ve test paketi gerçekçiliği

* **Sayım:** `tests/AegisPC.Tests` altında 60 C# test dosyası ve kaynakta 300 `[Fact]`/`[Theory]` özniteliği bulundu. Bu, teorilerin genişletilmiş test-vaka sayısı değildir.
* **Golden Test Suite [TEST EDİLDİ & DOĞRULANDI]:** `dotnet test AegisPC.sln --no-restore --filter "FullyQualifiedName~GoldenTestSuite" --logger "console;verbosity=normal"` çalıştırıldı; 5 test geçti, süre 2.6222 sn. Ham sonuç: `Toplam test sayısı: 5 / Geçti: 5`.
* **XAML bütünlük testleri [TEST EDİLDİ & DOĞRULANDI]:** ilgili filtre ile 2 test geçti. Bu sonuç AUD-02/AUD-10’u geçersiz kılmaz; testin kaynak kapsamı yukarıda kanıtlandı.
* **Tüm test paketi [HENÜZ SONUÇLANMADI]:** başlatıldı ancak bu rapor yazılırken komut nihai başarı/başarısızlık özeti vermeden 30 sn çağrı süresini aştı. Bu nedenle tüm paket için geçme iddiasında bulunmuyorum.

Rastgele örnek seçimi, tekrar edilebilirlik için `System.Random(20260907)` ile 60 `*Tests.cs` dosyası arasından yapıldı. Aşağıdaki sınıflandırma kaynak okunarak yapılmıştır:

| Rastgele seçilen test dosyası | Sınıflandırma |
|---|---|
| `DeepPeAnalyzerTests.cs` | Karışık: sentetik PE birim testleri; ayrıca gerçek Windows `explorer.exe`/`cmd.exe` üzerinde gerçek motor ve somut PE kararları. |
| `ScoringRegressionTests.cs` | Sentetik/mock dedektör verisi; gerçek disk/işletim sistemi yok. Güvenlik birim testi. |
| `PathHelperTests.cs` | Yol dizgesi birim testi; gerçek güvenlik kararı yok. Altyapı testi. |
| `EntropyCalculatorTests.cs` | Temp dosyaları kullanır, gerçek hesaplayıcıyı çağırır; somut entropi sonucu doğrular. Dar kapsamlı entegrasyon. |
| `AmsiAndWscTests.cs` | Kaynakta koşullu OS/servis denetimleri ve fakes bulunur; host durumuna bağlı duman testi, tam kötü örnek yürütmez. |
| `SecurityBenchmarkTests.cs` | Sentetik veri/ölçüm odaklı; güvenlik kararını uçtan uca doğrulamaz. Benchmark/duman testi. |
| `SafetyGuardTests.cs` | Temp dosyası ve gerçek transactional quarantine ile korumalı yol/şifreli restore kararını doğrular. Entegrasyon. |
| `DesktopFullScanTests.cs` | Temp diskte sentetik imzalı içerik ve gerçek FileScannerService kullanır; somut risk kararı doğrular. Entegrasyon, fakat gerçek zararlı değil. |
| `InstantFileArrivalProtectionTests.cs` | Temp diskte sentetik içerik ve gerçek gerçek-zamanlı motor/karantina kullanır; blok/karantina kararını doğrular. Entegrasyon, fakat gerçek zararlı değil. |
| `QuarantineVaultTests.cs` | Gerçek temp disk I/O ve gerçek karantina/restore bütünlüğü; zararlı sınıflandırması yok. Depolama entegrasyon testi. |

## İnceleme sonucu olmayan kontroller

* ArrayPool kullanımlarının kaynak taramasında görülen tüm `Rent` çağrıları ilgili `finally` içindeki `Return` ile eşleşti: `ArchiveSafetyScanner`, `EntropyCalculator`, `MalwareSignatureDatabase`, `PeAnalyzer`, `DeepPeAnalyzer`, `AntiEvasionDetector`. Bu, çalışma zamanı bellek profili değil statik denetim sonucudur.
* Risk seviye eşikleri `RiskScoringEngine.cs:261-267` uyarınca 40=Clean, 70=HighRisk, 85=ConfirmedMalicious’tır; 50=Suspicious. Golden05 bu bantları çalıştırıp geçti. 40 için özel test yoktur; switch mantığına göre sonuç Clean’dır.
* `PerformanceView.xaml.cs:23-30` telemetri timer’ını Loaded/Unloaded’da başlatıp durduruyor. Sürekli telemetri başlatan başka View tespit edilmedi; ProcessList/IncidentCenter yalnızca yüklemede tek seferlik async yükleme yapıyor.
* `App.xaml.cs:333-368` Dispatcher hataları için 3 saniyelik debounce içeriyor. AppDomain handler (`:324-331`) ayrı debounce içermez; süreç-sonlandırıcı istisna davranışı burada uçtan uca tetiklenmediği için bulguya çevrilmemiştir.

## Şüphecilik ve Doğrulama Notu

* Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: tüm test paketi bu turdaki 30 saniyelik komut penceresinde nihai özet üretmedi; sonuç bu nedenle rapora başarı olarak yazılmadı.
* Yüklü uygulamanın her tema geçişinde AUD-02’nin kullanıcıya görünür etkisini interaktif WPF oturumu ile tekrar etmedim. Kaynak anahtarın tanımsız olduğu ise statik olarak doğrulandı.
* AUD-03 için gerçek sertifikalı saldırgan örneği üretmedim; bulgu kod akışındaki önek eşleşmesi ve bypass koşuluna dayanır. Düzeltme öncesinde kanonik yol/reparse ve sertifika senaryolarıyla ayrı güvenlik regresyon testleri gereklidir.
