# 🏛️ ULTRON DEFENDER TOTAL SECURITY — CURRENT ARCHITECTURE

## 1. System Overview & Technology Stack

**Ultron Defender Total Security** is a modular Windows Endpoint Security platform developed in .NET 8 (C#) targeting modern 64-bit Windows systems (Windows 10 & 11).

```
┌─────────────────────────────────────────────────────────────────────────┐
│              ULTRON DEFENDER TOTAL SECURITY (Desktop UI / WPF)          │
├─────────────────────────────────────────────────────────────────────────┤
│                               UI Layer                                  │
│   • DashboardView     • ScanView          • IncidentCenterView          │
│   • QuarantineView    • BrowserSecurity   • RansomwareShieldView        │
│   • SettingsView      • NetworkProtection • PerformanceView             │
├─────────────────────────────────────────────────────────────────────────┤
│                          Application Layer                              │
│   • ViewModels (MVVM CommunityToolkit)   • Notification Aggregator      │
│   • ServiceIpcClient (NamedPipe)         • AutoStart / SystemTray       │
├─────────────────────────────────────────────────────────────────────────┤
│                     AegisPC.Security (Core Defense Engine)              │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────┐  │
│  │     DetectionHub      │  │     Risk Engine       │  │ SafetyGuard │  │
│  │ (Multi-Plugin Pipeline│  │ (Multi-Signal Scoring │  │(Canonical,  │  │
│  │  PE, Hash, Archive,   │  │  Evidence Attribution │  │ Protected,  │  │
│  │  Evasion, Injection)  │  │  Capping Matrix)      │  │ Symlink)    │  │
│  └───────────────────────┘  └───────────────────────┘  └─────────────┘  │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────┐  │
│  │   RealTimeProtection  │  │  Behavior & Lineage   │  │ Quaran-     │  │
│  │ (FileSystemWatcher    │  │ (ProcessLineage,      │  │ tine Vault  │  │
│  │  Channel Pipeline)    │  │  AttackChain, Memory) │  │ (AES-256)   │  │
│  └───────────────────────┘  └───────────────────────┘  └─────────────┘  │
├─────────────────────────────────────────────────────────────────────────┤
│                   Windows Service & Persistence Layer                   │
│   • AegisPC.Service (Background Worker)   • SQLite (aegis.db)           │
│   • NamedPipe IPC Server                  • DPAPI Master Key Vault      │
├─────────────────────────────────────────────────────────────────────────┤
│                       Kernel & Low-Level Boundary                       │
│   • Minifilter Driver C Source (drivers/AegisPC.Driver/ - UNCOMPILED)   │
│   • User-Mode Kernel Simulation / Contracts (KernelIpcService, Gating)  │
│   • AMSI Win32 P/Invoke (amsi.dll)                                      │
│   • Windows Security Center WMI (SecurityCenter2)                       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Project Hierarchy & Responsibilities

| Proje | Tür | Görevi ve Sorumluluk Alanı |
| :--- | :--- | :--- |
| **`AegisPC.Core`** | Class Library | Temel veri modelleri (`SecurityFinding`, `QuarantineEntry`, `AuditLog`, `SecurityIncident`), enum'lar ve yardımcı sınıflar. |
| **`AegisPC.Contracts`** | Class Library | Tüm güvenlik servis sözleşmeleri (`IDetectionHub`, `ISecureArchiveEngine`, `IDeepPeAnalyzer`, `IProtectedPathGuard`, `IKernelMinifilterContracts`, `INetworkProcessCorrelator`, `ISelfProtectionEngine`). |
| **`AegisPC.Security`** | Class Library | Antivirüs ve EDR motorlarının çekirdeği: `DetectionHub`, `DeepPeAnalyzer`, `RealTimeProtectionEngine`, `BehaviorEngine`, `TransactionalQuarantineEngine`, `AntiEvasionDetector`, `SecureArchiveEngine`, `StartupSecuritySweepService`. |
| **`AegisPC.Infrastructure`** | Class Library | SQLite veritabanı erişimi (`DatabaseService`), Denetim izi (`AuditLogService`), Windows Güvenlik Merkezi (`WindowsSecurityRegistrationService`). |
| **`AegisPC.BrowserSecurity`** | Class Library | Chromium (Chrome, Edge, Brave, Opera, Vivaldi) ve Firefox profil/eklenti güvenlik denetçisi (`BrowserSecurityService`). |
| **`AegisPC.Persistence`** | Class Library | Windows Başlangıç öğeleri, Kayıt Defteri Run/RunOnce, Görev Zamanlayıcı tarayıcıları (`StartupManagementService`). |
| **`AegisPC.Diagnostics`** | Class Library | Sistem sağlık kontrolü, kilitlenme analizcisi (`CrashAnalyzerService`), Windows Olay Günlüğü denetçisi. |
| **`AegisPC.Performance`** | Class Library | Sistem kaynak izleme (CPU, RAM, Disk I/O bütçelemesi), süreç listeleme ve performans kısıtlama. |
| **`AegisPC.Recommendations`** | Class Library | Güvenlik açığı ve optimizasyon önerileri motoru. |
| **`AegisPC.App`** | WPF Application | XAML tabanlı modern kullanıcı arayüzü, View'lar, ViewModel'lar, Bildirim pencereleri. |
| **`AegisPC.ServiceContracts`** | Class Library | Windows Servisi ile UI arasındaki NamedPipe IPC sözleşmeleri. |
| **`AegisPC.Service`** | Windows Service / Executable | Arka plan koruma çalışanı, NamedPipe sunucusu, zamanlanmış görev yürütücüsü. |
| **`AegisPC.ElevatedHelper`** | Tool Executable | UAC yükseltilmiş ayrıcalık gerektiren özel sistem işlemlerini gerçekleştiren yardımcı araç. |
| **`AegisPC.Tests`** | xUnit Test Project | 187 adet xUnit test içeren uçtan uca, birim ve regresyon test süiti. |

---

## 3. Güvenlik Olayı ve Karar Akışı (Data Flow)

1. **Giriş (Arrival / Event):**
   - `RealTimeProtectionEngine` dizin izleyicileri (`FileSystemWatcher`) dosya oluşturma/değiştirme olayını yakalar.
   - Olaylar sınırlandırılmış `Channel<NormalizedFileEvent>` kuyruğuna yazılır ve ardışık olarak işlenir.
2. **Normalizasyon & Kararlılık:**
   - Kanonik yol çözümlenir (`CanonicalPathResolver`), dosya yazımının bitmesi beklenir (`WaitForFileStabilityAsync`).
3. **Önbellek Sorgulama (MultiLayerScanCache):**
   - SHA-256 hesaplanır. L1 RAM LRU önbelleği kontrol edilir. Değişmeyen temiz dosyalar atlanır.
4. **Çok Eklentili Analiz (DetectionHub):**
   - `HashSignatureDetector` $\rightarrow$ `PeStaticDetector` $\rightarrow$ `DeepPeDetector` $\rightarrow$ `EntropyDetector` $\rightarrow$ `AntiEvasionDetectorPlugin` $\rightarrow$ `ArchiveDetectorPlugin` $\rightarrow$ `LocationReputationDetector`.
   - Her eklenti sisteme `SecurityEvidence` kanıt nesneleri sunar.
5. **Açıklanabilir Risk Motoru (RiskScoringEngine):**
   - Kanıtlar toplanır, kategori tavan puanı (capping) uygulanır.
   - Skorlama: `0–29 Clean`, `30–49 Low`, `50–69 Suspicious`, `70–84 High`, `85–100 Critical`.
6. **Müdahale ve Karantina:**
   - **Kural:** `UNKNOWN = ALLOW + LOG` (Bilinmeyen asla silinmez).
   - **Kural:** `CONFIRMED MALICIOUS = BLOCK + QUARANTINE`.
   - `TransactionalQuarantineEngine` ile DPAPI AES-256 atomik karantinası yürütülür (`ProtectedPathGuard` sistem dosyalarını korur).
