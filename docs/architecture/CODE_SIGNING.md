# Ultron Defender — Code Signing & Binary Integrity Guide

## 1. Genel Bakış
Windows işletim sisteminde Antivirüs / EDR yazılımlarının güvenilirliği, işletim sistemi ve kullanıcı güvenliği açısından ikili dosya (binary) imzalama kritik öneme sahiptir:
- **SmartScreen İtibarı:** İmzasız veya self-signed ikililer Windows Defender SmartScreen tarafından "Bilinmeyen Yayımcı" uyarısıyla engellenebilir.
- **Antivirüs / EDR Kendi Kendini Koruma:** Anti-Tamper mekanizmaları, `UltronDefender.exe` ve `AegisPC.Service.exe` dosyalarının değiştirilmediğini Authenticode imzası ile doğrular.
- **Kernel Sürücü Bütünlüğü:** 64-bit Windows sürücüleri (`AegisPC.sys`) Microsoft WHQL veya EV sertifikası olmadan yüklenemez.

---

## 2. Geliştirme & Test Ortamı (Test-Signing / Self-Signed)

Geliştirme ve yerel laboratuvar ortamında Authenticode imza akışını test etmek için aşağıdaki adımlar izlenir:

### Adım 1: Test Kök ve Kod İmzalama Sertifikası Oluşturma
Yönetici yetkili PowerShell konsolunda:
```powershell
# 1. Ultron Defender Test Root CA sertifikası oluştur
$rootCert = New-SelfSignedCertificate -Type Custom `
    -Subject "CN=Ultron Defender Root CA, O=Ultron Security Technologies, C=TR" `
    -KeyUsage CertSign, CRLSign `
    -KeyExportPolicy Exportable `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -HashAlgorithm SHA256

# 2. Kök sertifikayı Güvenilen Kök Sertifika Yetkilileri'ne ekle
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($rootCert)
$rootStore.Close()

# 3. Kök CA imzalı Kod İmzalama Sertifikası üret
$codeSignCert = New-SelfSignedCertificate `
    -Subject "CN=Ultron Defender Total Security, O=Ultron Security Technologies, C=TR" `
    -Signer $rootCert `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -KeyUsage DigitalSignature `
    -Type CodeSigningCert `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -HashAlgorithm SHA256

Write-Host "Test Kod İmzalama Sertifikası Thumbprint: $($codeSignCert.Thumbprint)"
```

### Adım 2: İkili Dosyaları SignTool ile İmzalama
Windows SDK içinde yer alan `signtool.exe` kullanılarak ikililer SHA-256 özeti ve RFC-3161 zaman damgasıyla imzalanır:
```powershell
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
$thumbprint = $codeSignCert.Thumbprint

& $signtool sign /sha1 $thumbprint `
    /fd SHA256 `
    /tr "http://timestamp.digicert.com" `
    /td SHA256 `
    /v "C:\Users\PC\Documents\gemini virüs program\AegisPC_App\UltronDefender.exe"

& $signtool sign /sha1 $thumbprint `
    /fd SHA256 `
    /tr "http://timestamp.digicert.com" `
    /td SHA256 `
    /v "C:\Users\PC\Documents\gemini virüs program\AegisPC_App\Service\AegisPC.Service.exe"
```

### Adım 3: İmzayı Doğrulama
```powershell
& $signtool verify /pa /v "C:\Users\PC\Documents\gemini virüs program\AegisPC_App\UltronDefender.exe"
```

---

## 3. Kernel Minifilter Sürücüsü Test-Signing
Windows 64-bit kernel güvenliği gereği test sürücülerinin çalışması için test imzalama modu açılmalıdır:
```cmd
bcdedit /set testsigning on
```
Sürücü `drivers\Build-And-Sign-Driver.ps1` betiği ile derlenip imzalandıktan sonra makine yeniden başlatılır.

---

## 4. Canlı / Üretim Ortamı (EV Code Signing Hazırlığı)

Canlı dağıtım sürümüne geçerken:
1. **EV Sertifikası:** FIPS 140-2 Level 2 uyumlu donanım USB belirteci (YubiKey / SafeNet) veya Cloud HSM (Azure Trusted Signing / DigiCert ONE).
2. **Azure Trusted Signing:** GitHub Actions veya CI hattına doğrudan bağlanabilen, HSM donanımı gerektirmeyen Microsoft onaylı bulut imzalama çözümü.
3. **Microsoft Partner Center (WHQL Attestation):** Kernel minifilter sürücüsü (`AegisPC.sys`) HLK testleri tamamlanarak Microsoft Hardware Dev Center portalına teslim edilir ve resmi Microsoft imzası alınır.
