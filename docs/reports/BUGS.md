# Ultron Defender — Master Bug List & Fix Log

Bu doküman, Ultron Defender projesinde tespit edilen, yeniden üretilen (reproduced), kök nedeni bulunan (root-cause analyzed), düzeltilen ve regresyon testleri yazılan tüm hataların teknik listesidir.

---

## 1. Master Bug Tablosu

| Bug ID | Şiddet (Severity) | Bileşen | Başlık | Durum | Regresyon Testi |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BUG-001** | **CRITICAL** | `RiskScoringEngine` | Sistem Dosyalarında Hatalı Pozitif (dmloader.dll / ssh-keygen.exe PUP olarak algılanıyordu) | **FIXED** | `Test_BenignFile_Dmloader_NotFlaggedAsPUP` (PASS) |
| **BUG-002** | **CRITICAL** | `QuarantineService` | Kilitli ve Korumalı Dosyalarda Karantinanın Başarısız Olması & UI Bildirim Eksikliği | **FIXED** | `Test_QuarantineService_EncryptsAndWipesOriginalFile` (PASS) |
| **BUG-003** | **HIGH** | `RealTimeProtection` | FileSystemWatcher Buffer Overflow & Storm Kayıpları (Default 8KB Buffer) | **FIXED** | `Test_FileFlood_500Events_HandledGracefully` (PASS) |
| **BUG-004** | **HIGH** | `QuarantineService` | Non-Atomic Index Kaydı Nedeniyle Çökmede quarantine_index.json Bozulma Riski | **FIXED** | `Test_QuarantineService_AtomicIndexSave_PreservesData` (PASS) |
| **BUG-005** | **HIGH** | `ProcessTermination` | PID Reuse Riski (Farklı bir meşru süreç aynı PID'yi aldığında yanlış sonlandırma riski) | **FIXED** | `Test_ProcessTermination_PidReuseCheck_RejectsMismatchedPath` (PASS) |
| **BUG-006** | **MEDIUM** | `RealTimeProtection` | Sadece Downloads Dizinine Bağlı Kalma (Documents, ProgramData, Startup eksikti) | **FIXED** | Path Expansion Verified (PASS) |

---

## 2. Detaylı Hata İnceleme Raporları

### BUG-001: Sistem Dosyalarında Hatalı Pozitif (PUP False Positive)
- **Şiddet:** CRITICAL
- **Etkilenen Bileşen:** `AegisPC.Security.Scanning.RiskScoringEngine`
- **Semptom:** Hızlı ve tam taramada `C:\Windows\System32\dmloader.dll` ve `ssh-keygen.exe` gibi 18 temiz Microsoft dosyası "Yüksek Riskli Dosya" olarak listeleniyordu.
- **Kök Neden:** `PupNamePatterns` listesinde yer alan `"loader"` ve `"keygen"` kelimeleri kaba alt dize (raw substring) olarak aranıyordu. Ayrıca `isDefiniteFinding` skoru 20 (Clean) olan dosyaları da listeye sokuyordu.
- **Düzeltme:** Kelime sınırı token eşleştirmesi getirildi. Microsoft imzalı ve sistem dizinlerindeki dosyalar PUP kelime analizinden muaf tutuldu.
- **Regresyon:** `Test_BenignFile_Dmloader_NotFlaggedAsPUP`

### BUG-002: Karantina Motorunun Kilitli Dosyalarda Çökmesi
- **Şiddet:** CRITICAL
- **Etkilenen Bileşen:** `AegisPC.Security.Scanning.QuarantineService`
- **Semptom:** Karantinaya al butonuna tıklandığında dosyalar silinmiyor, arayüz sessiz kalıyordu.
- **Kök Neden:** Dosya açıkken `File.ReadAllBytes` veya `File.Delete` `IOException` fırlatıyor, yakalanan hata UI'a iletilmiyordu.
- **Düzeltme:** `FileShare.ReadWrite | FileShare.Delete` akışı kuruldu, kilitleyen süreçler tespit edilip düşürüldü, öznitelikler sıfırlandı ve `MoveFileEx(DELAY_UNTIL_REBOOT)` zamanlanmış silme eklendi.
- **Regresyon:** `Test_QuarantineService_EncryptsAndWipesOriginalFile`

### BUG-003: FileSystemWatcher Olay Fırtınasında Olay Kaybı
- **Şiddet:** HIGH
- **Etkilenen Bileşen:** `AegisPC.Security.RealTime.RealTimeProtectionEngine`
- **Semptom:** Çok sayıda dosya arka arkaya yazıldığında watcher sessizce durabiliyor veya olay kaçırabiliyordu.
- **Kök Neden:** `InternalBufferSize` varsayılan 8 KB değerindeydi ve `watcher.Error` dinlenmiyordu.
- **Düzeltme:** `InternalBufferSize` 64 KB'a çıkarıldı ve hata durumunda otomatik restart ekleyen `watcher.Error` bağlandı.
- **Regresyon:** `Test_FileFlood_500Events_HandledGracefully`

### BUG-004: Karantina İndeksi Atomik Yazım Açığı
- **Şiddet:** HIGH
- **Etkilenen Bileşen:** `AegisPC.Security.Scanning.QuarantineService.SaveIndexToDisk`
- **Semptom:** Diske yazım sırasında elektrik kesintisi veya çökme olursa `quarantine_index.json` 0 bayt kalıp bozuluyordu.
- **Kök Neden:** `File.WriteAllText` doğrudan hedef dosyayı eziyordu.
- **Düzeltme:** Önce geçici `.tmp` dosyasına yazılıp `File.Move(..., overwrite: true)` ile atomik dosya değişimi yapıldı.
- **Regresyon:** `Test_QuarantineService_AtomicIndexSave_PreservesData`

### BUG-005: PID Reuse Süreç Sonlandırma Güvenlik Açığı
- **Şiddet:** HIGH
- **Etkilenen Bileşen:** `AegisPC.Performance.Process.ProcessTerminationService`
- **Semptom:** Eski bir zararlı süreç öldükten sonra Windows aynı PID'yi başka bir güvenli programa tahsis ettiğinde yanlış programın kapatılma riski.
- **Kök Neden:** Sadece int `PID` parametresine göre `Process.GetProcessById(pid).Kill()` çağrısı yapılması.
- **Düzeltme:** `TerminateProcessSafelyAsync` ile beklenen çalıştırılabilir dosya yolu (`expectedExecutablePath`) ve süreç adı eşleşmesi zorunlu kılındı.
- **Regresyon:** `Test_ProcessTermination_PidReuseCheck_RejectsMismatchedPath`
