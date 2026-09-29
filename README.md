# 🛡️ Ultron Defender Total Security

[![Status](https://img.shields.io/badge/status-experimental%20preview-orange.svg)](docs/architecture/FEATURE_STATUS.md)
[![Review](https://img.shields.io/badge/review-2026--09--28-blue.svg)](docs/research/ANTIVIRUS_SAFETY_2026-09-28.md)
[![Target Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20(x64)-blue.svg)](#)
[![Framework](https://img.shields.io/badge/.NET-8.0%20WPF-purple.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-Master%20Index-blue.svg)](docs/README.md)

**Ultron Defender Total Security** is an experimental, open-source Windows security project written in **C# (.NET 8), WPF XAML, Native Win32 APIs and SQLite**. It includes file scanning, user-mode event monitoring, heuristic analysis and an encrypted quarantine vault. These components do not establish commercial antivirus efficacy or production readiness.

---

### 🇹🇷 Proje Hakkında (About in Turkish)

3.2.1 geliştirme dalında Release **474 seçili karma regresyon testi** geçti (29 Eylül 2026); bu sayı zararlı yakalama oranı değildir. Zamanlayıcı, rapor geçmişi, SHA-256 bağlı istisnalar, kaynak göstergesi ve ZIP/JAR akışları için önceki düzeltmelerin yanı sıra yanlış bildirim, başlangıç eylem kesinliği, YARA güven düzeyi ve bulut yanıt sınırı düzeltmeleri bulunur. [Güncel güvenlik sınırları ve test kanıtı](docs/research/ANTIVIRUS_SAFETY_2026-09-28.md) · [önceki iş akışı incelemesi](docs/research/WORKFLOW_REVIEW_2026-09-27.md).

Bu .NET 8 sürümü **Windows 7 desteklemez**; Windows 10/11 x64 hedeflerinde sürüm ve edisyon uyumu ayrıca doğrulanmalıdır ([Microsoft destek matrisi](https://learn.microsoft.com/dotnet/core/install/windows)). İmzalı kernel koruması veya Defender'dan üstünlük iddiası yoktur. Kurulum paketini yalnız oluşturmak için `./build_and_deploy.ps1` kullanılır; varsayılan masaüstü/servis/Defender ayarlarını değiştirmez. Kurulum EXE'sini çalıştırmak ayrı, yönetici yetkisi gerektiren işlemdir.
Ultron Defender, açıklanabilir dosya analizi ve donanıma göre uyarlanan tarama üzerinde geliştirilen bir önizleme projesidir. Mevcut gerçek zamanlı izleme, seçili klasörlerde kullanıcı-modu dosya olayları ve süreç başladıktan sonraki gözlemlere dayanır; normal kurulum imzalı kernel sürücüsünü etkinleştirmez ve yürütme öncesi engelleme garantisi vermez. Yanlış pozitiflerin sıfır olduğu iddia edilmez. Okul/iş bilgisayarlarında dağıtımdan önce yönetici onayı ve izole pilot gerekir; mevcut Defender/kurumsal korumayı kapatmayın. [Güncel kapsam ve sınırlamalar](docs/research/ANTIVIRUS_SAFETY_2026-09-28.md).

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
dotnet test tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj --filter "FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests&FullyQualifiedName!~ScanViewModel_CancelCommand"
dotnet test tests/AegisPC.Trust.Tests/AegisPC.Trust.Tests.csproj
```

Bu seçili koşu zararsız geçici dosyalar ve karar/altyapı testlerini kullanır; gerçek zararlı yazılım etkinlik testi değildir. Ana test projesi canlı süreç/kimlik bilgisi testleri ve fiziksel EICAR fikstürü de içerir: tüm paketi sıradan okul/iş bilgisayarında çalıştırmayın. Dağıtım/kurulum scriptleri sistemi değiştirir; yukarıdaki yayınlama komutları uygulamayı kurmaz.

---

### 📚 Dokümantasyon ve Mimari Haritası (Documentation & Architecture)
* 🗺️ **Mimari Haritası:** [`docs/architecture/CURRENT_ARCHITECTURE.md`](docs/architecture/CURRENT_ARCHITECTURE.md) & [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md)
* 📋 **Özellik Durum Matrisi:** [`docs/architecture/FEATURE_STATUS.md`](docs/architecture/FEATURE_STATUS.md)
* 📖 **Tüm Dokümanlar İndeksi:** [`docs/README.md`](docs/README.md) (Mimari, Araştırma, Raporlar ve AI Yönergeleri)
* 📜 **Sürüm Değişiklikleri:** [`CHANGELOG.md`](CHANGELOG.md) | **Lisans:** [MIT License](LICENSE)
