# ULTRON DEFENDER (AegisPC) — MASTER PLAN v1.0
> Bu dosya projenin tek doğruluk kaynağıdır. Başka bir AI'da çalıştırılırken BU DOSYANIN DIŞINA ÇIKILMAZ; kapsam değişikliği yapılmaz, yeni "daha iyi fikirler" eklenmez. Görev sırası F0→F6'dır. Her faz bitiminde docs/architecture/FEATURE_STATUS.md güncellenir ve `dotnet test tests\AegisPC.Tests\AegisPC.Tests.csproj -c Debug --filter "Category!=LiveSample"` PASS çıktısı kanıtlanmadan faz kapatılmaz.

---

## BÖLÜM A — ELEŞTİREL DEĞERLENDİRME (0-10 puan, 2026-09 itibarıyla gerçek kod denetimine dayalı)

| # | Alan | Puan | Gerekçe |
|---|------|------|---------|
| 1 | İmza/IOC altyapısı | **7** | MalwareBazaar gerçek besleme (Auth-Key header) çalışıyor; ama sadece hash tabanlı, YARA yok, besleme bootstrap (ilk gün 10binlerce imza) eksik. |
| 2 | Tarama motoru mimarisi | **8** | Content-over-extension, arşiv güvenliği, çok katmanlı önbellek, imza-once-hash hızlı yolu, donanım duyarlı eşzamanlılık — mimari doğru. Windows kökünde yüzeysel gezme dün giderildi; hâlâ MSRT aşaması Quick'ta çalışıp %12'yi yiyor. |
| 3 | Gerçek zamanlı koruma | **5** | FileSystemWatcher post-op (dosya zaten yazıldıktan sonra görür); otomatik karantina politikası yok (bulgular çoğunlukla "Uyarıldı" kalır); pre-exec engelleme simülasyon. ETW izleme var ama karar vermiyor. |
| 4 | Karantina sistemi | **9** | Gerçek AES-256+DPAPI kasa, atomic hareket, geri yükleme orijinal yola, "sil" = kriptografik ezme + File.Delete + denetim kaydı. En sağlam modül. Eksik: otomatik karantina politika bağlantısı. |
| 5 | Davranış motoru / EDR | **6** | ETW süreç izleme, süreç soy ağacı, kanarya dosyaları, MITRE korelasyon — parçalar var ama tarama bulgularıyla korele edilmiyor, otomatik aksiyon yok. |
| 6 | UI/UX | **6** | Dashboard Codex-tarzı sakin karanlık (iyi); ama: tarayıcı sayfası dark bug'lı, süreç yöneticisi sıralamasız, sayfa geçiş animasyonu yok, splash yok, tarama penceresi renk dili kırmızı-ağır. |
| 7 | Kaynak yönetimi | **7** | AdaptiveScanResourceManager gerçekten koordinatöre bağlı; RAM katmanları (4/8/16GB) mantığı var; ama 3-4 örtüşen profil sınıfı var ve tarama başında kullanıcı seçimi yok. |
| 8 | Kod sağlığı | **4** | ~127 sessiz catch, CI yok, ikililer imzasız, installer servis kurmuyor + mutex ismi uyuşmuyor, test sayısı dokümanlar arasında kayıyor. |
| 9 | Test kültürü | **7** | 537 test — rakam iyi; ama canlı malware örnekli test sayısı çok az, flaky 1 test (Lab01, zaman aşımı), doküman-test sayısı tutarsızlığı. |
| 10 | Genel AV yeteneği | **5.5** | "Temizlikçi + alarm" seviyesi. Bilinen hash'leri bulur, ransomware davranışı yakalar, karantina gerçek. Başlatılmadan engelleyemez, imzasız zararlıyı güvenle tespit edemez, kendini koruyamaz. Defender'ın YANINDA anlamlı, tek başına yetersiz. |

**Genel: 6.4/10** — Mühendislik iskeleti sağlam, "engelleme" katmanı eksik. Planın hedefi 10 içinde: imza 9 / RT koruma 8 / politika 8 / sağlık 8 / genel 7.5+.

---

## BÖLÜM B — TESPİT EDİLMİŞ HATA ve BUG LİSTESİ (denetim bulguları)

| ID | Şiddet | Bulgu | Durum |
|----|--------|-------|-------|
| B1 | Yüksek | Canlı akış tablosunda fare tekerleği kaydırma çalışmıyordu (sayfa PreviewMouseWheel tüm olayları yutuyordu) | **Düzeltildi** (DashboardView.xaml.cs — DataGrid atası görülünce olay bırakılıyor) |
| B2 | Yüksek | Bildirim spam'i: 20 dk'lık arka plan taraması aynı statik bulguları her seferinde yeniden bildiriyordu + her tarama için çift toast | **Düzeltildi** (BackgroundProtectionService._notifiedFindingPaths + IsAutomaticScanInProgress + 30 dk tehdit cooldown) |
| B3 | Yüksek | "Tam Tarama" C:\Windows kökünde yalnızca System32/SysWOW64/Temp'e iniyordu (WinSxS, Installer, ProgramData atlanıyordu) → sahte hızlı tam tarama izlenimi | **Düzeltildi** (DirectoryWalker tam kapsam) |
| B4 | Yüksek | Kaynak profil metinleri (ör. "1024 MB Kota") gerçek davranışı yansıtmıyordu; 3-4 örtüşen profil sınıfı | **Kısmen** (AdaptiveScanResourceManager bağlandı; tek kaynak zorunluluğu F4-G5'te) |
| B5 | Orta | "Uyarıldı" bulguları karantina listesinde yok ama bildirim tıklaması karantinaya götürüyor → kullanıcı dosyayı bulamıyor | **Plan** (F1) |
| B6 | Orta | Inno Setup `AppMutex` ile koddaki mutex adı uyuşmuyor (`Local\UltronDefender_SingleInstance_<user>`) → installer çalışan uygulamayı göremiyor | **Plan** (F6) |
| B7 | Orta | `installer.iss` "AegisPC Protection Service"i kurmuyor/çalıştırmıyor → kurulu kullanıcıda servis tabanlı koruma yok | **Plan** (F6) |
| B8 | Orta | İmza DB'si ProgramData'da ACL sıkılaştırmasına rağmen `ImportThreatHashes` INSERT OR REPLACE: düşük yetkili yazıcı bulguları zehirleyebilir; checksum koruması var ama delta doğrulama yok | **Plan** (F6) |
| B9 | Orta | Tarayıcı Güvenliği sayfası dark temada beyaz seçim şeridi/açıklama kutusu bug'ı | **Plan** (F4) |
| B10 | Düşük | Lab01 EICAR testi makine yükünde flaky (5 sn watcher zaman aşımı) | **Plan** (F6: zaman aşımı 15 sn + retry) |
| B11 | Düşük | `_notifiedFindingPaths`, `_recentlyScanned`, `_threatToastCooldown` koleksiyonları sınırsız büyüyor (prune yok) | **Plan** (F6: 10k üstünde LRU temizliği) |
| B12 | Düşük | ~127 sessiz `catch {}` bloğu; kritik olanları tarama/karantina/imza doğrulamasında | **Plan** (F6) |
| B13 | Düşük | Doküman/test sayısı tutarsızlığı (README 246, PROJECT_SCOPE 251, gerçek 537) | **Plan** (F6: CI çıktısı tek kaynak) |

---

## BÖLÜM C — UYGULAMA FAZLARI (sırayla, sapma yasak)

### FAZ 0 — Çalışma kuralları (her fazda geçerli)
- TDD: önce test, sonra kod. `dotnet test` PASS kanıtı olmadan görev bitti denmez.
- Sessiz catch yasak: her catch Serilog'a yazar; dosya bazlı hatalar `ScanError`/`FailedFiles` sayacına düşer.
- `AegisPC.Contracts` arayüzleri kırılmaz; yeni yetenek = yeni arayüz + DI kaydı.
- Hash/IOC/byte-deseni MODEL ÜRETMEZ; kaynak (MalwareBazaar, Microsoft docs) belirtilmeden tehdit verisi yazılmaz.
- UI/tema talebi motor fazında, motor talebi UI fazında YAPILMAZ.
- Aynı dosyada iki oturum paralel çalışmaz (çakışma geçmişi var).

### FAZ 1 — Politika motoru: "bul"dan "engelle"ye (en yüksek öncelik)
1. `src/AegisPC.Security/Policy/PolicyEngine.cs`: karar tablosu —
   - RiskScore ≥ 85 VE Category ∈ {KnownMalwareHash, ConfirmedMalicious} → OTOMATİK karantina (`QuarantineService.QuarantineFileAsync`) + "engellendi" bildirimi (tekilleştirme hattından).
   - RiskScore 60-84 → Olay Merkezi + "Uyarıldı"; bildirim tıklaması Olay Merkezi'ne gider (karantinaya değil → B5 düzelir).
   - SafetyGuard (ProtectedPathGuard/ReparsePointGuard) her otomatik aksiyonun ÖNÜNDE çalışır; imzalı Microsoft ikilisi asla otomatik karantinaya girmez.
2. Ayarlar: `EnableAutoQuarantine` (varsayılan true), `AutoQuarantineThreshold=85` — AppSettings + Ayarlar UI'ına anahtar.
3. ScanCoordinatorService tamamlama akışına PolicyEngine'i bağla; her otomatik aksiyon AuditLog'a.
4. Testler: EICAR düşürülünce otomatik karantinada; temiz imzalı dosya asla otomatik karantinada değil; "Uyarıldı" bulgu bildirim tıklaması Olay Merkezi'ne gider.

### FAZ 2 — YARA motoru (bulma gücünü 54→10binlerce imzaya taşır)
1. `src/AegisPC.Security/Detection/YaraEngine/`: yara-x C API P/Invoke (veya libyara); seçim gerekçesi 5 satır.
2. Kural dizini `C:\ProgramData\UltronDefender\yara\`; 3 doğrulanmış örnek kural (kaynak belirtilerek).
3. DetectionHub 14. dedektör: YaraDetector → SecurityEvidence(kural adı, metaveri) + sev=100.
4. ThreatFeedUpdater'a kural seti yenileme adımı.
5. Test: EICAR'ın YARA ile yakalanması.

### FAZ 3 — Pre-exec kapısı (ETW ile başlamadan engelleme)
1. TraceEvent ile Microsoft-Windows-Kernel-Process aboneliği (ProcessStart + ImageLoad).
2. Yeni süreç imajı senkron taranır (hash önbelleği → YARA → DetectionHub).
3. Skor ≥ AutoQuarantineThreshold → NtSuspendProcess → karantina → sonlandır. Suspend penceresi ≤ 500 ms; aşılırsa bırak + SECURITY log.
4. Beyaz liste ÖNCE: CriticalProcesses + geçerli Microsoft zincir imzası olan süreç asla askıya alınmaz.
5. ETW düşerse FileSystemWatcher'a geri dönüş; koruma asla tamamen durmaz.
6. Test: EICAR.exe çalıştırma denemesi askıya alınmalı (simülasyon testi + elle doğrulama talimatı).

### FAZ 4 — UI/UX (GEMINI_PROMPT_UI.md'deki 7 görev aynen: geçiş animasyonları, splash, süreç yöneticisi RAM/CPU/GPU sıralama, tarayıcı dark bug=B9, tarama penceresi yeşil/kırmızı, kaynak profili sorusu + tarama içinden RAM ayarı, kota metni tek kaynak=B4)

### FAZ 5 — Yeni sistem önerileri (bu faza girmeden önce F1-F4 bitmeli; sırayla)
1. **Tarama Zamanlayıcısı 2.0**: pil modunda otomatik Sakin profil, oyuncu modu tespiti (fullscreen süreç varken tarama erteleme), disk aktivitesi >80% IOPS iken sınırlandırma.
2. **Geri Alma Günlüğü**: otomatik karantinalar için 30 günlük "cofa" — tek tıkla toplu geri alma + "neden karantinalandı" karar zinciri görünümü (yanlış pozitif güveni).
3. **İtibar Hizmeti (yerel)**: dosyaların ilk görülme tarihi + hangi uygulamadan geldiği + puan geçmişi; "bu dosya 6 aydır sorunsuz" sinyali risk skoruna -10 katkı.
4. **Kendi Kendini Güncelleme**: imza DB'sini güncelleme gibi sürüm güncelleme hattı (manifest + imza doğrulaması; imzasız güncelleme asla uygulanmaz).
5. **Olay Zaman Çizelgesi Dışa Aktarım**: EDR kayıtlarını CSV/JSON export (portfolio değeri yüksek, maliyeti düşük).
6. **Sahte Sürüm Dedektörü**: klasörde birden çok UltronDefender.exe publish kopyası varsa kullanıcıyı tek güncel konuma yönlendirme (eski exe karışıklığı yaşandı).

### FAZ 6 — Sağlık borcu (sonda ama ihbarsız)
1. B6: installer.iss AppMutex'i koddakiyle eşitle (veya kodda ikinci global mutex aç).
2. B7: installer servis kurulumu + `sc.exe` başlangıç adımı (opsiyonel checkbox).
3. B8: `ImportThreatHashes`'a delta doğrulama (sadece Append, source="MalwareBazaar" dışına yazma izni yok).
4. B10: Lab01 zaman aşımı 15 sn + 1 retry.
5. B11: üç koleksiyona 10k LRU prune.
6. B12: 127 sessiz catch'in kritik %20'sini (tarama/karantina/imza) logla; kalanı Inventory listesi olarak docs'a.
7. B13: README/CHANGELOG test sayılarını CI çıktısına bağla; GitHub Actions workflow (build+test, windows-latest) ekle.
8. B6-B7 bitince ikili imzalama notu: EV sertifika alınana kadar "test-signing" belgesi docs'a.

---

## BÖLÜM D — YASAKLAR (tüm oturumlar için)
1. FEATURE_STATUS'da canlı test kanıtı olmadan VERIFIED yazmak yasak; kanıt yoksa IMPLEMENTED/PARTIAL bırak.
2. Yeni framework/ NuGet bağımlılığı yalnızca gerekçeyle (TraceEvent, yara-x hariç şu an kilitli).
3. Sahte lisans/renk/kapasite METİNLERİ üretmek yasak (geçmişte "PRO LİSANS", "1024 MB Kota" yaşandı — ekrandaki her sayı gerçek hesaptan gelmek zorunda).
4. Bu plan dosyasındaki faz sırası ve kapsam değiştirilemez; yeni fikirler plana "FAZ 5.+" olarak ÖNERİ satırı eklenir, uygulanmaz.
5. Oturum bitişinde: değişen dosya listesi + test özeti + FEATURE_STATUS farkı raporlanır.
