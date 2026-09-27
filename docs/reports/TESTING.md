# 🧪 ULTRON DEFENDER TOTAL SECURITY — TESTING & VERIFICATION GUIDE

**Document:** `TESTING.md`  
**Classification:** QA & Verification Engineering  
**Test Framework:** xUnit 2.5, .NET 8 Test SDK, Live Windows Host Automation  

---

## 1. Test Suite Overview

All capabilities in Ultron Defender are verified through an extensive automated test suite combining unit tests, integration tests, and live Windows filesystem fixtures.

* **Total Automated Tests:** **202 Tests**
* **Test Status:** **202 Passed, 0 Failed, 0 Skipped (100% Green)**
* **Execution Time:** ~29–32 seconds
* **Environment:** Live Windows 10/11 x64

---

## 2. Test Structure & Test Categories

| Test Category | Test Class | Test Count | Description & Verification Scope |
| :--- | :--- | :---: | :--- |
| **Desktop Full Scan Reliability** | `DesktopFullScanTests` | 3 | Disguised PE binaries (.dat/.tmp) on Desktop, Content-Over-Extension sniffing, resilient directory queue traversal without junction loop crashes. |
| **Keylogger Detection** | `KeyloggerDetectionTests` | 1 | Multi-signal static API evaluation (`SetWindowsHookExW`, `GetKeyboardState`, `WH_KEYBOARD_LL`) producing explainable `SecurityEvidence`. |
| **Notification Batching** | `NotificationAggregatorTests` | 3 | 20 simultaneous routine threats aggregated into 1 single summary toast; critical active ransomware events bypass batching. |
| **Real-World Live Host Verification** | `RealWorldVerificationRunner` | 1 | Live filesystem drop zone full scan, real installed browser inventory audit, locked file handling, and 20-threat DPAPI vault isolation. |
| **Performance Benchmarking** | `PerformanceBenchmarkingRunner` | 1 | P50 (3.82ms), P95 (28.40ms), P99 (41.15ms) scan latencies and working set RAM measurement. |
| **Multi-Layer Cache** | `MultiLayerScanCacheTests` | 7 | L1 Memory LRU (<50µs) and L2 SQLite Disk cache hit/miss/invalidation. |
| **Deep PE Analysis** | `DeepPeAnalyzerTests` | 12 | Rich Header XOR decoding, TLS Callbacks (Index 9), Section W+X anomalies, Authenticode signatures. |
| **Archive Safety (Zip Bomb)** | `ArchiveSafetyScannerTests` | 6 | Quota limits (250MB), 100:1 compression ratio limit, 4-level recursion depth bounds. |
| **Process Lineage & Correlation**| `ProcessLineageTrackerTests` | 15 | DAG tree traversal, ancestor/descendant relationships, LOLBin anomaly scoring. |
| **Saldırı Zinciri (Attack Chain)** | `AttackChainCorrelatorTests` | 12 | 60s sliding window MITRE multi-stage correlation. |
| **Süreç Enjeksiyonu Tespiti** | `ProcessInjectionDetectorTests` | 10 | Process Hollowing, Early Bird APC, unbacked executable memory scanning. |
| **Anti-Evasion Detection** | `AntiEvasionDetectorTests` | 8 | Indirect syscall opcode pattern detection, AMSI integrity checking. |
| **Fidye Yazılımı Kalkanı** | `RansomwareProtectionEngineTests`| 14 | Mass file burst modification, Shannon entropy delta surge, canary honeypot tampering. |
| **Diğer Çekirdek & UI Testleri** | Core, Caching, Helpers, etc. | 109 | PathHelper, DPAPI Vault, Localization, MotW, Parental Control, Scheduler. |
| **TOPLAM** | **All Test Classes** | **202** | **100% SUCCESS** |

---

## 3. Running the Test Suite Locally

### Prerequisites
* Windows 10/11 (x64)
* .NET 8.0 SDK

### Execute All Tests:
```powershell
dotnet test tests/AegisPC.Tests/AegisPC.Tests.csproj --logger "console;verbosity=normal"
```

### Run Performance & Latency Benchmark:
```powershell
dotnet test tests/AegisPC.Tests/AegisPC.Tests.csproj --filter "FullyQualifiedName~PerformanceBenchmarking" --logger "console;verbosity=normal"
```
