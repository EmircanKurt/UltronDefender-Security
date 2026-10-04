# 🛡️ Ultron Defender Total Security

[![Status](https://img.shields.io/badge/status-experimental%20preview-orange.svg)](docs/architecture/FEATURE_STATUS.md)
[![Review](https://img.shields.io/badge/review-2026--10--04-blue.svg)](docs/research/FREE_EDITION_AI_REVIEW_2026-10-04.md)
[![Target Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20(x64)-blue.svg)](#)
[![Framework](https://img.shields.io/badge/.NET-8.0%20WPF-purple.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-Master%20Index-blue.svg)](docs/README.md)

**Ultron Defender Total Security** is an experimental, open-source Windows security project written in **C# (.NET 8), WPF XAML, Native Win32 APIs and SQLite**. It includes file scanning, user-mode event monitoring, heuristic analysis and an encrypted quarantine vault. These components do not establish commercial antivirus efficacy or production readiness.

### Ücretsiz sürüm

Mevcut sürüm ücretsizdir; ürün aktivasyon anahtarı, abonelik veya süre sınırı gerektirmez. Gelecekteki ücretli sürüm bu sürümün bir özelliği değildir. MIT kaynak lisansı ürün aktivasyonu anlamına gelmez. Windows koruma hizmeti, kasa şifreleme anahtarları ve isteğe bağlı üçüncü taraf API kimlikleri teknik bileşenlerdir; ödeme şartı değildir. Arka plan hizmetinin doğrulanamaması gerçek bir koruma/kapsam uyarısıdır, lisans uyarısı değildir. Sabit örnek PRO anahtarı/süre alanları kaldırıldı; son güvenli Review koşusunda 939 geçti / 1 VM-yetki testi atlandı. İçindeki 69 AI/politika/tercih vakası zararlı yakalama oranı değildir. [Ücretsiz sürüm, test ayrımı ve GitHub denetimi](docs/research/FREE_EDITION_AI_REVIEW_2026-10-04.md).

Ultron AI is a local, handwritten review/policy layer, not an LLM or a calibrated malware-probability model. The latest slice fixes observation-only behavior decisions and terminal scan failures, adds tested permit/receipt contracts and an accessible animated robot. **Independent Guardian protection and production native actions remain gated.** [Implementation evidence and unfinished gates](docs/research/ULTRON_AI_CHIEF_PHASE1_2026-10-04.md).

The subsequent UI slice adds a service-acknowledged optional AI-review switch with two disable confirmations, persistent preference synchronization, wheel/viewport fixes and bounded privacy-safe diagnostics. Safe selected regressions: 937 passed / 1 VM-privilege skip; these are not a malware detection rate. The expected protection service was not found on the development machine; prepared unsigned artifacts were not installed. The repeated runtime scan failure's exception is still unknown. [Current evidence and limitations](docs/research/ULTRON_AI_SHIELD_UI_FIXES_2026-10-04.md).

---

### 🇹🇷 Proje Hakkında (About in Turkish)

4 Ekim 2026 yerel geliştirme dilimi; yapılandırılmış kanıt politikası, taze servis sağlığı, uzantıdan bağımsız içerik sınıflandırma, servis sahipli kasa ve USB/disk/HID keşfi üzerinde ilerledi. Test sayıları ve kapsam [güncel uygulama raporundadır](docs/research/ULTRON_RT_USB_IMPLEMENTATION_2026-10-04.md); seçili benign regresyonlar zararlı yakalama oranı değildir. **Yayın engelleri:** kullanıcı-bağlamı taşıması tamamlanana kadar arayüzden geri yükleme/manüel karantina reddedilir; standart kullanıcıya özel RT tehdit bildirimi henüz yoktur. Fidye sezgileri tek başına süreç öldürmez; HID keşfi firmware güvenliğini veya ilk kötü tuşun engellenmesini kanıtlamaz. [Önceki güvenlik düzeltmeleri](docs/research/ANTIVIRUS_SAFETY_2026-09-28.md).

Bu .NET 8 sürümü **Windows 7 desteklemez**; Windows 10/11 x64 hedeflerinde sürüm ve edisyon uyumu ayrıca doğrulanmalıdır ([Microsoft destek matrisi](https://learn.microsoft.com/dotnet/core/install/windows)). İmzalı kernel koruması veya Defender'dan üstünlük iddiası yoktur. Kurulum paketini yalnız oluşturmak için `./build_and_deploy.ps1` kullanılır; varsayılan masaüstü/servis/Defender ayarlarını değiştirmez. Kurulum EXE'sini çalıştırmak ayrı, yönetici yetkisi gerektiren işlemdir.
Ultron Defender, açıklanabilir dosya analizi ve donanıma göre uyarlanan tarama üzerinde geliştirilen bir önizleme projesidir. Mevcut gerçek zamanlı izleme, seçili klasörlerde kullanıcı-modu dosya olayları ve süreç başladıktan sonraki gözlemlere dayanır; normal kurulum imzalı kernel sürücüsünü etkinleştirmez ve yürütme öncesi engelleme garantisi vermez. Yanlış pozitiflerin sıfır olduğu iddia edilmez. Okul/iş bilgisayarlarında dağıtımdan önce yönetici onayı ve izole pilot gerekir; mevcut Defender/kurumsal korumayı kapatmayın. [Güncel gerçek zamanlı kapsam ve doğrulama sınırları](docs/research/REALTIME_COVERAGE_PHASE1_2026-09-30.md).

---

### 💻 Nasıl Derlenir? (Build from Source)
Gereksinimler: Windows 10/11 (x64), .NET 8.0 SDK, Inno Setup 6.
```powershell
git clone https://github.com/EmircanKurt/UltronDefender-Security.git
cd UltronDefender-Security
dotnet build AegisPC.sln -c Release
dotnet publish src/AegisPC.App/AegisPC.App.csproj -c Release -o artifacts/preview/app
dotnet publish src/AegisPC.Service/AegisPC.Service.csproj -c Release -o artifacts/preview/service
```

### 🧪 Nasıl Test Edilir? (Run Tests)
```powershell
dotnet test tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --filter "FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests"
dotnet test tests/AegisPC.Trust.Tests/AegisPC.Trust.Tests.csproj -c Release
```

4 Ekim son ücretsiz sürüm Release koşusunda Review **939 geçti / 1 VM-yetki testi atlandı / 0 başarısız**. Önceki Trust **35/35** sonucu bu tur yeniden koşulmadı; ortak vakalar iki kez sayılmaz. Bu koşu zararsız geçici dosyalar ve karar/altyapı testlerini kullanır; gerçek zararlı yazılım etkinlik testi değildir. Ana test projesi canlı süreç/kimlik bilgisi testleri ve fiziksel EICAR fikstürü de içerir: tüm paketi sıradan okul/iş bilgisayarında çalıştırmayın. Dağıtım/kurulum scriptleri sistemi değiştirir; yukarıdaki yayınlama komutları uygulamayı kurmaz. [Koşular ve kapsam](docs/research/FREE_EDITION_AI_REVIEW_2026-10-04.md).

Kasa symlink testi mevcut host yetkisi nedeniyle VM kapısına ayrılmıştır; atlanan test geçti sayılmaz. Yeni kaynak değişiklikleri kurulu eski EXE'ye otomatik uygulanmaz; bu dilimde imzalı kurulum veya canlı servis pilotu yapılmamıştır.

---

### 📚 Dokümantasyon ve Mimari Haritası (Documentation & Architecture)
* 🗺️ **Mimari Haritası:** [`docs/architecture/CURRENT_ARCHITECTURE.md`](docs/architecture/CURRENT_ARCHITECTURE.md) & [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md)
* 📋 **Özellik Durum Matrisi:** [`docs/architecture/FEATURE_STATUS.md`](docs/architecture/FEATURE_STATUS.md)
* 📖 **Tüm Dokümanlar İndeksi:** [`docs/README.md`](docs/README.md) (Mimari, Araştırma, Raporlar ve AI Yönergeleri)
* 📜 **Sürüm Değişiklikleri:** [`CHANGELOG.md`](CHANGELOG.md) | **Lisans:** [MIT License](LICENSE)
