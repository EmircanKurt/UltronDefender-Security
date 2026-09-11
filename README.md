# 🛡️ Ultron Defender Total Security (v3.2.0)

> [!NOTE]
> **Açık Kaynak Uç Nokta Güvenlik ve Antivirüs Savunma Platformu**  
> Güvenlik araştırmacıları, geliştiriciler ve bireysel kullanıcılar için Windows Internals, heuristik tarama ve proaktif siber savunma kalkanı.

[![Status](https://img.shields.io/badge/status-v3.2.0%20Release%20Ready-brightgreen.svg)](#)
[![Build & Test Status](https://img.shields.io/badge/tests-616%20passed%20(100%25)-brightgreen.svg)](#testing)
[![Target Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20(x64)-blue.svg)](#supported-windows-versions)
[![Framework](https://img.shields.io/badge/.NET-8.0%20WPF-purple.svg)](#build-from-source)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Setup](https://img.shields.io/badge/Setup-UltronDefenderSetup.exe-success.svg)](UltronDefenderSetup.exe)

**Ultron Defender Total Security** is a high-performance, open-source Windows endpoint protection and advanced malware defense platform written in **C# (.NET 8), WPF XAML, Native Win32 APIs, SQLite, and 14 modular detection plugins**.

Designed from real-world adversarial incident forensics, Ultron Defender brings commercial-grade heuristic scanning, deep PE disassembly, AMSI in-memory script inspection, ransomware decoy honeypots, and atomic DPAPI AES-256 quarantine vault isolation to everyone for free.

---

## 📸 Arayüz & Görseller (Visual Showcase)

### 0. Resmi Siber Kalkan Logosu (Official Cyber Spartan Shield Logo)
![Official Logo](docs/screenshots/logo.png)

### 1. Modern & Sade Kontrol Paneli (Executive Dashboard)
<img width="1296" height="873" alt="Ekran görüntüsü 2026-09-09 160358" src="https://github.com/user-attachments/assets/153efeae-9fc4-49b5-a9b3-ac93db7ca65a" />



### 2. ESET Tarzı Canlı Animasyonlu Tarayıcı Penceresi (Active Scanner)
<img width="866" height="566" alt="Ekran görüntüsü 2026-09-09 161057 - Kopya" src="https://github.com/user-attachments/assets/03536966-a5e3-4848-9414-97cd015a0083" />


### 3. Çoklu Seçimli Tehdit Analiz Tablosu (Threat Scan Results)
<img width="1289" height="1027" alt="Ekran görüntüsü 2026-09-11 113613" src="https://github.com/user-attachments/assets/b5b80432-182a-465f-ac4c-f742c7a160a8" />


### 4. Sessiz & Kayan ESET Bildirim Kartı (Silent Threat Notification)
<img width="464" height="160" alt="Ekran görüntüsü 2026-09-10 160532" src="https://github.com/user-attachments/assets/43cd542c-0ed3-45c6-953f-b3f2779bc7be" />


---

## 🇹🇷 Neden Bu Projeyi Geliştirdim? (Türkçe Açıklama)

Bu proje, bilgisayarıma internet tarayıcısı üzerinden bırakılan izinsiz bir zararlı dosya sonucunda kişisel hesaplarımın ve verilerimin tehlikeye girdiği gerçek bir güvenlik ihlalinden sonra doğdu.

Olayın ardından bir güvenlik araştırmacısı gözüyle sistemi incelerken geleneksel antivirüslerin şu kritik açıklarını fark ettim:
* **Uzantı Aldatmacası:** Saldırganlar `.exe` uzantısını gizleyip `.bin`, `.dat` veya `.tmp` yaptığında birçok tarayıcı dosyayı atlıyor.
* **Görünmezlik:** Masaüstüne veya İndirilenler klasörüne yeni bir zararlı düştüğünde güvenlik yazılımı onu bazen saatlerce fark etmiyor.
* **Sahte Alarmlar:** Meşru oyun modları (`.lua`, `.so`, crackli oyun kayıtları) gereksiz yere silinirken, gerçek zararlı komut dosyaları (LOLBin, DDE CSV enjeksiyonu) kaçırılabiliyor.

Bu tecrübeyi fırsata dönüştürerek Windows Internals, Minifilter mimarisi, PE başlık analizi ve süreç soyağacı takibini temel alan **Ultron Defender Total Security**'yi geliştirdim. Amacım kapalı kutu antivirüslerin aksine **%100 şeffaf, açıklanabilir ve test edilebilir** bir açık kaynak savunma kalkanı sunmaktır.

---

## 🚀 Öne Çıkan Özellikler (Key Highlights)

* 🛑 **Kesintisiz Tarama Durum Yönetimi (State Machine):** Tek bir gerçek durum makinesi (`ScanCoordinatorService`), çalışan iş parçacıklarının işlemi derhal bırakmasını sağlayan hard-stop ve dosya bazlı `CancellationToken` kontrolleri.
* 🎯 **Sıfır Yanlış Pozitif Politikası:** `TrustedSoftwarePolicy` ile Microsoft ve ticari imzalı uygulamalar için tam güven bypass'ı; UPX ve entropi yalnızca bağımsız tehdit göstergeleriyle birleştiğinde ağırlık kazanır.
* 🚀 **SSD/NVMe Uyumlu Çok Çekirdekli Tarama Motoru:** `AdaptiveScanResourceManager` ile donanıma göre (cores*2/3/4) paralel işçi havuzu, SSD sürücülerde sıfır gecikme, 65k kuyruk kapasitesi.
* 🛡️ **Gelişmiş Fidye Kalkanı & CFA (Controlled Folder Access):** Korumalı klasör kapıları (Protected Folders), Windows Restart Manager (`rstrtmgr.dll`) ile kilitli süreç tespiti, çift yönlü bal küpü (canary trap) dosya yemleri ve yetkisiz süreçlerin anında engellenmesi.
* 🔌 **Ring-0 Minifilter & fltLib IPC:** `KernelIpcService` üzerinden `FilterConnectCommunicationPort` ve `FilterReplyMessage` çift yönlü haberleşmesi. Sürücü yüklü olmadığında dürüstçe `Degraded (User-Mode Only)` raporlama.
* 📦 **Birleşik Karantina & Olay Merkezi:** DPAPI AES-256 ile şifrelenmiş tehditleri güvenle inceler, siler veya tek tıkla geri yükler.
* 🔕 **Sessiz Kayan Bildirimler:** Rahatsız edici sistem sesleri olmadan, ekranın sağ altında açılan modern kırmızı uyarı kartı (`NotificationAggregator`).

---

## 🧪 Canlı Test ve Doğrulama (Live Test Suite)

Tüm modüller 616 otomatik birim ve entegrasyon testi ile test edilmiştir:

```bash
dotnet test tests/AegisPC.Tests/AegisPC.Tests.csproj -c Release
```

```text
Toplam 1 test dosyası belirtilen desenle eşleşti.
Başarılı!  - Başarısız: 0, Başarılı: 616, Atlanan: 0, Toplam: 616, Süre: ~3 dk
```

| Senaryo | Dosya Türü | Tespit Türü | Sonuç |
|---|---|---|:---:|
| **EICAR Testi** | `.txt / .com` | Bilinen Zararlı İmza | **✅ 100/100 (Engellendi)** |
| **Fidye Yazılımı** | `.bat / .locked` | Gölge Kopyaları Silme / Şifreleme Uzantısı | **✅ 100/100 (Engellendi)** |
| **CSV Enjeksiyonu**| `.csv` | DDE Formül Enjeksiyonu (`=cmd\|...`) | **✅ 50/100 (Yakaladı)** |
| **Arşiv Dropper** | `.zip` | ZIP İçi Powershell Dropper | **✅ 90/100 (Engellendi)** |
| **Meşru Kurulum / Oyun Yaması** | `.exe / .dll` | Dijital İmza / Meşru Dizin Güveni | **✅ 0/100 (Temiz Kabul Edildi)** |

---

## 🛠️ Kernel Sürücüsü ve Dağıtım (Driver & AMSI Distribution)

### 1. Kernel Minifilter Sürücüsü Derleme & İmzalama (Test-Signing):
```powershell
# Sürücü önkoşullarını kontrol edin (WDK / MSBuild):
powershell -ExecutionPolicy Bypass -File drivers\Test-DriverPrerequisites.ps1

# Sürücüyü derleyin ve test sertifikasıyla imzalayın:
powershell -ExecutionPolicy Bypass -File drivers\Build-And-Sign-Driver.ps1 -Configuration Release -Sign
```

### 2. AMSI Sağlayıcı Kaydı (In-Process Script Scanning):
```powershell
# AMSI sağlayıcı COM DLL'ini kaydedin:
powershell -ExecutionPolicy Bypass -File tools\AmsiProvider\Register-AmsiProvider.ps1 -DllPath tools\AmsiProvider\AmsiProvider.dll -Register
```

---

## 💻 Projeyi Kaynaktan Derleme (Build from Source)

### Gereksinimler:
* Windows 10 / 11 (x64)
* .NET 8.0 SDK
* Inno Setup 6 (Kurulum paketi derlemek için)

```powershell
# 1. Depoyu klonlayın
git clone https://github.com/EmircanKurt/UltronDefender-Security.git
cd UltronDefender-Security

# 2. Tek komutla derleyin, test edin ve kurulum paketini üretin:
powershell -ExecutionPolicy Bypass -File .\build_and_deploy.ps1
```

---

## 📄 Lisans (License)
Bu proje [MIT Lisansı](LICENSE) altında açık kaynaklı olarak paylaşılmaktadır.
