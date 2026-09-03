# Ultron Defender (AegisPC) — Proje Kapsamı ve Test Doğrulama Sınırları

> **Belge:** `PROJECT_SCOPE.md`  
> **Son Güncelleme:** 2026-09-03  
> **Uyum:** `AI_SELF_AUDIT.md` (İlke 1, 5, 7) & `AI_GUIDELINES.md`  

---

## 1. Genel Durum ve Test Özeti

Proje genelinde toplam **251 otomatik test metodu** bulunmaktadır ve tamamı başarılıdır (%100 Pass). 

`AI_SELF_AUDIT.md` İlke 7 (Test Sayısı Şişirme Yasağı) uyarınca, toplam test sayısı toptan "güvenlik testi" olarak sunulamaz. Testlerin niteliği ve doğrulamaya esas teşkil eden dayanakları aşağıdaki gerçekçi kategorizasyon tablosunda sınıflandırılmıştır.

---

## 2. Gerçekçi Test Dağılımı ve Doğrulama Seviyeleri

| Seviye / Kategori | Adet | Kapsam ve Koşullar (İlke 7) | Örnekler |
| :--- | :---: | :--- | :--- |
| **Golden Test Suite (Asli Değişmezler)** | **5** | • Gerçek disk I/O ve izole sandbox klasörleri<br>• Gerçek motor orkestratörleri<br>• EICAR tespiti, sıfır self-detection, sıfır false-positive, AES-GCM karantina bütünlüğü, risk skor eşikleri | `Golden01_EicarDetection`, `Golden02_ZeroSelfDetection`, `Golden04_QuarantineAndRestore` |
| **Güvenlik Entegrasyon Testleri** | **~130** | • Gerçek dosya sistemi I/O veya canlı işletim sistemi kaynakları<br>• Gerçek tarayıcı/kalkan motorları (mock kullanılmaz)<br>• Somut güvenlik kararları (`RiskScore >= 90`, karantina tetiklenmesi, dosya silinmesi/engellenmesi, NT status doğrulaması)<br>*Not: Zararlı yükler kontrollü laboratuvar için sentetiktir (EICAR, sentetik PE bölümleri, dummy batch).* | `Lab01_EicarFileDrop`, `CanaryDecoy_IsDeployedToDisk`, `Test_DesktopSyntheticMalware`, `KernelGatingEngine_BlocksMalicious` |
| **Güvenlik Birim Testleri** | **~58** | • İzole algoritma veya veri yapısı testleri<br>• Gerçek disk I/O yerine sentetik byte dizisi veya bellek içi model nesnesi (`FileAnalysisResult`)<br>• Mock kullanılmasa dahi gerçek OS/disk bileşenini uçtan uca çalıştırmaz | `AntiDebuggingApis`, `PupScoringTests`, `EntropyCalculatorTests`, `CheckHash_EicarSha256` |
| **Altyapı, Duman ve Yardımcı Testler** | **~58** | • Güvenlik kararı değil, çökme/çalışma kontrolü veya operasyonel davranış<br>• DI container bağımlılık çözümleme, path canonicalization, yerelleştirme (i18n), UI thread asenkronluk testi, network adaptör listeleme | `Test_DnsAdapters_Enumeration`, `Test_StartupSweep_DoesNotBlockUI`, `DiContainerIntegrityTests`, `PathHelperTests` |
| **TOPLAM** | **251** | **Tüm xUnit Test Metotları (0 Başarısız, %100 Başarılı)** | — |

---

## 3. Doğrulama Sınırları ve Kapsam Notları

1. **Sentetik vs. Canlı Zararlı:** Laboratuvar testlerindeki hiçbir senaryo canlı, vahşi ortamda (in-the-wild) bulunan aktif bir kötü amaçlı yazılım örneğini diske indirmez. Testler; EICAR standart dizgisi, sentetik PE başlık manipülasyonları, kontrollü simülatörler ve sahte Canary dosyaları kullanılarak yürütülür.
2. **Kernel Modu Simülasyonu:** `KernelMinifilterTests` kapsamındaki testler gerçek bir Ring 0 minifilter sürücüsü çalıştırmaz; kullanıcı modu IPC ve Pre-Op karar mantığı simülasyonunu test eder.
3. **Kategorizasyon Tahmini:** 251 testin detaylı metod ayrımı `test_audit_report.md` içerisinde yer almakta olup, yaklaşık ~130 / ~58 / ~58 dağılımı İlke 7 koşulları ekseninde belirlenmiştir.
