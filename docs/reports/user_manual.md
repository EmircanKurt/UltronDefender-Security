# Ultron Defender Total Security (AegisPC)
## Kurulum, Yönetim ve Kullanıcı Kılavuzu (v3.5.0)

---

### 1. Genel Bakış ve Mimari Yapı

**Ultron Defender Total Security (AegisPC)**, kurumsal ve son kullanıcı Windows sistemleri için geliştirilmiş, yerel çevrimdışı (offline-first) çalışan yeni nesil bir EDR ve Antivirüs güvenlik platformudur.

Sistem 4 temel savunma katmanından oluşur:

1. **Kernel Minifilter Sürücüsü (`AegisFilter.sys`):**
   - Dosya sistemi G/Ç (I/O) işlemlerini donanım seviyesinde izler.
   - Dosya oluşturma ve yürütme anında (`PreCreate`) zararlı yazılımları `STATUS_ACCESS_DENIED (0xC0000022)` koduyla engeller.
   - Standart virüsten koruma irtifasında (`Altitude: 320500`) çalışır.

2. **Windows Çekirdek Koruma Servisi (`AegisPCProtectionService`):**
   - Windows arka planında `LocalSystem` yetkisiyle `start= auto` modunda çalışır.
   - Hata anında kendini otomatik olarak yeniden başlatır (Self-Healing Recovery).
   - Güvenli Named Pipe (`\\.\pipe\AegisPC_ServicePipe`) ile kullanıcı arayüzüne telemetri sağlar.

3. **Gelişmiş ETW ve Anti-Tamper Motoru:**
   - 256 MB döngüsel ETW oturumu ile süreç başlatma ve imaj yükleme olaylarını izler.
   - Temp/Downloads dizininden DLL enjeksiyonu ve bilinen istismar sürücülerini (BYOVD - `RTCore64.sys`, `mhyprot2.sys`) yakalar.
   - Servis durdurma (`sc config disabled`), registry manipülasyonu (`Start=4`) ve silme girişimlerini anında engelleyip saldırgan süreci sonlandırır.

4. **Kullanıcı Arayüzü (`UltronDefender.exe`):**
   - Modern WPF tabanlı Türkçe/İngilizce destekli Fluent kontrol paneli.
   - Hızlı, Tam ve Özel Tarama modları.
   - Karantina kasası yönetimi ve canlı aktivite izleme.

---

### 2. Sistem Gereksinimleri

| Bileşen | Asgari Gereksinim | Önerilen Gereksinim |
| :--- | :--- | :--- |
| **İşletim Sistemi** | Windows 10 (1903+) / Windows 11 / Windows Server 2016+ (x64) | Windows 11 (23H2+) 64-bit |
| **İşlemci (CPU)** | 2 Çekirdek 2.0 GHz x64 | 4 Çekirdek 3.0+ GHz x64 |
| **Bellek (RAM)** | 4 GB RAM | 8 GB+ RAM |
| **Disk Alanı** | 500 MB boş alan | 2 GB NVMe SSD |
| **Yetki Düzeyi** | Administrator (Yönetici) | Administrator (Yönetici) |

---

### 3. Otomatik ve Hızlı Kurulum (`install.ps1`)

Kurulum işlemi tamamen otomatikleştirilmiş olup 1 dakikadan kısa sürede tamamlanır:

#### Adım Adım Kurulum:
1. PowerShell'i **Yönetici Olarak Çalıştırın** (Run as Administrator).
2. Proje veya kurulum dizinine gidin:
   ```powershell
   cd "C:\Path\To\UltronDefender"
   ```
3. Kurulum betiğini çalıştırın:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\install.ps1
   ```

#### Gelişmiş Kurulum Parametreleri:
- `-SkipDriver` : Sürücü yüklemesini atlar (yalnızca servis ve kullanıcı arayüzü kurulur).
- `-SkipStart`  : Kurulum sonrasında servisi otomatik başlatmaz.
- `-NoDesktopShortcut` : Masaüstü kısayolu oluşturmaz.
- `-Force` : Kullanıcı onayı istemeden sessiz (unattended) kurulum yapar.

---

### 4. Çevrimdışı USB İmza Güncelleme Mekanizması

İnternet bağlantısı olmayan izole (Air-gapped) sistemlerde imza veritabanı harici USB bellek üzerinden güncellenir:

1. Güncelleme paketini (`signatures_packed.bin`) bir USB belleğin kök dizinine veya `UltronUpdate` klasörüne kopyalayın:
   - `E:\UltronUpdate\signatures_packed.bin`
   - ya da `E:\AegisUpdate\signatures_packed.bin`
2. USB belleği AegisPC kurulu bilgisayara takın.
3. Arka planda çalışan `UltronDefender_UsbUpdateWatcher` zamanlanmış görevi veya `Sync-UsbSignatures.ps1` betiği USB'deki imzaları otomatik algılar.
4. Dosya boyutu ve bütünlüğü doğrulandıktan sonra `C:\ProgramData\UltronDefender\signatures\` dizinine atomik olarak kopyalanır ve servis belleği güncellenir.
5. Manuel tetikleme için:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\UltronDefender\Tools\Sync-UsbSignatures.ps1"
   ```

---

### 5. Sağlık ve Teşhis Doğrulaması (`verify_install.ps1`)

Kurulumun doğruluğunu ve koruma bileşenlerinin aktifliğini kontrol etmek için:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\verify_install.ps1
```

Bu betik şu 6 kontrolü icra eder ve renkli özet rapor sunar:
- **[PASS]** `AegisPCProtectionService` durumu (`Running`, `start= auto`)
- **[PASS]** `AegisFilter` Minifilter sürücü bağlantısı (`fltmc filters` - Altitude `320500`)
- **[PASS]** UI ve Servis ikili dosya bütünlüğü
- **[PASS]** 500+ tehdit imzası içeren veritabanı dosyası
- **[PASS]** Named Pipe IPC haberleşme kanalı
- **[PASS]** Registry ve Windows Explorer sağ-tık entegrasyonu

---

### 6. Temiz Kaldırma Kılavuzu (`uninstall.ps1`)

Sistemi ilk günkü temiz durumuna döndürmek için:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\uninstall.ps1 -Force
```

#### Yapılan Temizlik Adımları:
1. Tüm UI ve Servis süreçleri güvenle durdurulur.
2. `fltmc unload AegisFilter` ile sürücü bellekten boşaltılır ve PnP sürücü deposundan silinir.
3. `sc delete AegisPCProtectionService` ile servis kaydı kaldırılır.
4. `hosts` dosyasına eklenen engelleme listeleri geri alınır (rollback) ve DNS önbelleği temizlenir.
5. Windows Başlangıç (`Run`), Shell menüleri ve Registry anahtarları silinir.
6. Kısayollar ve Program Files / ProgramData dizinleri tamamen temizlenir.

---
© 2026 Ultron Security Technologies. Tüm hakları saklıdır.
