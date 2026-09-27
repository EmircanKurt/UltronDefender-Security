# Faz 2: Güven sınırı ve yayın protokolü

## Güvenlik kararları

- Authenticode imzası zararsızlık kanıtı değildir. Tam yayıncı adı yalnızca yardımcı itibar bilgisidir.
- `SignatureVerifier` kilitli dosyayı `WinVerifyTrust` ile doğrular. Katalog üyeliği ayrıca `WTD_CHOICE_CATALOG` ile doğrulanır. Metadata okunması güven doğrulamasının yerine geçmez.
- `SignatureInfo.VerificationStatus`: Unknown / Unsigned / Valid / Invalid. Eski boolean alanlar API uyumu için korunmuştur; bütün tüketicilerin ayrıntılı duruma geçişi henüz tamamlanmamıştır.
- İptal isteği native çağrı öncesi/sonrası kontrol edilir. Devam eden senkron WinTrust çağrısı zorla kesilemez. Revocation için cache-only policy kullanılır; doğrulanamayan durum geçerli sayılmaz.
- FileHashMatcher imzadan dolayı taramayı atlamaz; bilinen zararlı hash açık kullanıcı güveninden önce değerlendirilir. Hash hesaplaması tamamlanmış tarama olarak önbelleğe yazılmaz.
- Tamamlanmış tarama önbelleği boyut/tarihe ek olarak SHA-256 ile yeniden doğrulanır; güncel hash veritabanı sorgulanır. Çözüldü/beyaz liste kararları normal yolda yeniden değerlendirilir.
- Puanlama ile gerçek zamanlı/çekirdek kararındaki yayıncı kaynaklı tam atlamalar kaldırılmıştır. Bu, başka modüllerdeki tüm muafiyetlerin kaldırıldığı anlamına gelmez.

## İmzalı güncelleme sözleşmesi

`AutoUpdateService` constructor parametreleri:

- `trustedManifestPublicKeyPem`: güvenilir dağıtımla verilen RSA açık anahtarı. İndirilen manifestten alınmaz. Eksikse güncelleme reddedilir.
- `installedVersion`: çalışan ürünün gerçek sürümü. Varsayılan assembly sürümüdür; dağıtım bunu açıkça sağlamalıdır.
- `updateBaseDirectory`: hazırlama/yedek dizini; testlerde ayrı geçici dizin kullanılır.

Manifestin ürün, sürüm, URL, SHA-256, boyut, son geçerlilik zamanı ve yayın bilgileri `UpdateManifestVerifier.GetSigningPayload` çıktısıyla imzalanır. Algoritma RSA-PSS/SHA-256, en az 3072 bit. Özel anahtar uygulamaya veya repoya konulmaz. Test anahtarları geçici, yalnızca bellektedir; üretimde kullanılmaz.

İndirici yalnız HTTPS kabul eder; varsayılan HTTP istemcisi redirect izlemez. Enjekte edilen istemci de redirect izlemeyecek şekilde yapılandırılmalıdır. Manifest 64 KiB, paket 512 MiB ile sınırlandırılmıştır. Paket boyutu ve hash doğrulanır. Uygulama sırasında aynı açık dosyadan tekrar hash hesaplanıp kopyalanır. Tüm uzantılar manifest doğrulamasına tabidir; `.bin` gibi uzantılar güven kontrolünü atlatmaz.

Authenticode ile manifest imzası farklıdır: güncelleme yetkilendirmesini sabitlenmiş yayın anahtarı sağlar. Ürün EXE'lerinin Windows kod imzalama sertifikasıyla imzalanması ayrıca kurulacak dağıtım adımıdır.

## Üretime açılmadan önce gerekenler

1. Gerçek yayın anahtarının güvenli oluşturulması/saklanması, açık anahtarın dağıtıma sabitlenmesi, anahtar rotasyonu ve gerçek sürüm kaynağının tanımlanması.
2. Güncelleyicinin uygulama/servis zamanlayıcısına bağlanması. Bu sınıfın test edilmesi, canlı güncelleme servisi kurulduğu anlamına gelmez.
3. Yeniden başlatmalar arasında korunan sürüm/replay kaydı ve kurtarma günlüğü. Mevcut doğrulama makbuzları/yedek eşlemeleri bellektedir; restart sonrası yeniden indirme gerekir. Geri alma yalnız aynı instance'ın son hedef yedeği içindir.
4. Yetkili dizin ACL'leri ve dizin yeniden adlandırma/reparse yarışlarının handle tabanlı doğrulanması; mevcut reparse ön kontrolü tek başına tüm yarışları çözmez.
5. Çok dosyalı paket, servis kapatma/açma, güç kesintisi ve yarıda kalmış kurulum testleri. Mevcut uygulama tek dosya değiştirmedir.
6. Katalog/çoklu imza/sertifika iptali matrisi, ayrıntılı Unknown durumunun tüm UI ve politika tüketicilerine taşınması, sürümlü kural-politika önbelleği.

## Doğrulama

Zararsız güven testleri ayrı projede çalıştırılabilir:

```powershell
dotnet test tests/AegisPC.Trust.Tests/AegisPC.Trust.Tests.csproj -c Release
```

Paketler restore edildikten sonra `./scripts/Test-TrustCore.ps1` tercih edilebilir; boş/atlanmış test çalışmasını TRX sayaçlarından başarısız sayar ve önceki sonuçların üzerine yazmaz.

Çevrimdışı paketler önceden mevcutsa `NuGet.offline.config` ile restore yapılabilir. Ana test derlemesinde canlı müdahale testleri de bulunur; bu küçük proje sadece belirtilen iki zararsız test kaynak dosyasını derler. Defender devre dışı bırakılmamalı ve test çalıştırmak için karantina geri alınmamalıdır.

Kaynaklar: [WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust), [WINTRUST_CATALOG_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_catalog_info).
