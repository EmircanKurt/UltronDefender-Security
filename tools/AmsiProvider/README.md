# Ultron Defender AMSI Provider (AmsiProvider.dll)

## Genel Bakış ve Mimari

Bu bileşen, Windows Antimalware Scan Interface (AMSI) mimarisine üçüncü taraf bir sağlayıcı (Provider) olarak entegre olan **unmanaged C++ COM DLL** uygulamasıdır.

Windows; PowerShell (`powershell.exe`), Windows Script Host (`wscript.exe`, `cscript.exe`), MSBuild ve Microsoft Office VBA makroları gibi çalışma zamanlarında çalıştırılan dinamik ve bellek içi (in-memory) kod bloklarını `amsi.dll` üzerinden kayıtlı sağlayıcılara iletir.

```
[ PowerShell / Office / WSH ]
            │
            ▼ (amsi.dll)
[ HKLM\SOFTWARE\Microsoft\AMSI\Providers\{638DC8E4-1B1C-4328-8C67-DF52445EFA10} ]
            │
            ▼
[ AmsiProvider.dll (CAmsiProvider : IAmsiProvider) ]
            │
            ▼ (Named Pipe: \\.\pipe\AegisPC_ScanPipe)
[ AegisPC.Service (DetectionHub + YaraEngine + RiskScoringEngine) ]
            │
            ▼ (Karar: AMSI_RESULT_DETECTED [32768] veya AMSI_RESULT_CLEAN [0])
[ PowerShell: Komut İptal Edildi / İzin Verildi ]
```

---

## Dışa Aktarılan Arayüzler ve API'ler

### 1. COM Arabirimleri
- `IAmsiProvider` (IID: `b2bacd80-97ab-4ff3-8f0b-46a2a0937a85`)
- `IClassFactory` (IID: `00000001-0000-0000-C000-000000000046`)
- COM CLSID: `{638DC8E4-1B1C-4328-8C67-DF52445EFA10}`

### 2. Dışa Aktarılan C/Win32 Fonksiyonları
- `AmsiInitialize(PCWSTR appName, HAMSICONTEXT* amsiContext)`
- `AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION* amsiSession)`
- `AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession)`
- `AmsiScanString(HAMSICONTEXT amsiContext, PCWSTR string, PCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result)`
- `AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, PCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result)`

---

## Kritik Güvenlik, İmzalama ve Çakışma Notları

### 1. Durum Bildirimi (Status)
> **DURUM: PARTIAL - imza bekliyor**

Bu bileşen kaynak kod seviyesinde tam fonksiyonel olarak geliştirilmiş ve derleme şablonu hazırlanmıştır; ancak üretim ortamında Windows işletim sistemi tarafından doğrudan yüklenip çalıştırılabilmesi için geçerli bir **Microsoft Authenticode / WHQL / ELAM** dijital imzası gerekmektedir.

### 2. Windows Defender ile Çakışma Riski
- Windows Defender (`MpProvider.dll` veya `MsMpEng.exe`), varsayılan AMSI sağlayıcısı olarak kayıtlıdır.
- Windows AMSI, sistemde birden çok sağlayıcı kayıtlı olduğunda hepsini sırayla çağırır ve **en yüksek risk skorunu (en katı engelleme kararını)** baz alır.
- Ultron Defender AMSI Provider kaydedildiğinde Windows Defender ile paralel çalışır. Ancak imzasız bir DLL kaydedilirse Windows Defender veya AppLocker/WDAC (Windows Defender Application Control) bu DLL'in PowerShell süreçlerine enjekte olmasını `STATUS_ACCESS_DENIED` ile engelleyebilir.
- Bu nedenle DLL imzalanmadan canlı üretim ortamına kaydedilmemeli, test için Test-Signing modu tercih edilmelidir.

### 3. Kod İmzalama Gereksinimi (Code Signing)
Windows 10 ve 11 işletim sistemlerinde `amsi.dll`, korumalı süreçlerin (PPL - Protected Process Light) veya kısıtlı yetkili script motorlarının içine harici DLL yüklerken dijital imza doğrulaması yapabilir.
1. **Üretim Dağıtımı (Production):**
   - Microsoft WHQL / Partner Center üzerinden imzalanmış EV Code Signing sertifikası veya Microsoft ELAM (Early Launch Anti-Malware) sertifikası gereklidir.
2. **Geliştirme / Test Ortamı:**
   - Test-signing modunu açmak için yönetici PowerShell'de:
     ```cmd
     bcdedit /set testsigning on
     ```
   - Kendinden imzalı (self-signed) test sertifikası oluşturup Trusted Root / Trusted Publishers deposuna ekleyerek DLL'i imzalayabilirsiniz:
     ```powershell
     New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=UltronDefender Test" -CertStoreLocation "Cert:\LocalMachine\My"
     Set-AuthenticodeSignature -FilePath "AmsiProvider.dll" -Certificate (Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert)
     ```

---

## Kurulum ve Kayıt (Registration)

### Kayıt Etme:
Yönetici PowerShell terminalinde:
```powershell
.\Register-AmsiProvider.ps1 -DllPath "C:\Program Files\UltronDefender\AmsiProvider.dll"
```

### Sistemden Kaldırma:
```powershell
.\Register-AmsiProvider.ps1 -Unregister
```
