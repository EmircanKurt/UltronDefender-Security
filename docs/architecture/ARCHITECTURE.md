# 🏗️ ULTRON DEFENDER TOTAL SECURITY — ARCHITECTURE SPECIFICATION

**Document:** `ARCHITECTURE.md`  
**Classification:** System Architecture & Dataflow Blueprint  
**Target Platform:** Windows 10 / Windows 11 (x64 / ARM64)  
**Technology Stack:** C# (.NET 8), WPF, XAML, Win32 APIs, SQLite, Inno Setup  

---

## 1. High-Level System Architecture

Ultron Defender is architected around the **Separation of Interception, Analysis, and Presentation Layers**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. PRESENTATION LAYER (AegisPC.App - WPF / XAML Modern UI)                  │
│    - Lepo WPF-UI Dashboard                                                  │
│    - Scan Coordinator View (Full / Quick / Custom / Memory)                 │
│    - Threat Center & Security Findings                                      │
│    - DPAPI Quarantine Vault Explorer & Restore                              │
│    - Real-Time Protection Toggles & Settings                                │
│    - Single-Instance Mutex & Focus Manager                                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Named Pipe IPC / Local RPC
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. CORE SECURITY SERVICE (AegisPC.Service - Windows Service / Background)   │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ A. TELEMETRY & EVENT PIPELINE                                         │  │
│  │    - FileSystemWatcher (Drop Zone Watchdog: Desktop/Downloads/Temp)   │  │
│  │    - ProcessMonitorService (Win32 Toolhelp32 & Lineage DAG Graph)     │  │
│  │    - AmsiScanService (Win32 amsi.dll in-memory script provider)       │  │
│  │    - RansomwareProtectionEngine (Canary traps + Burst Entropy Guard)  │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │ Canonicalized Event                   │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ B. DETECTIONHUB & MODULAR DETECTOR PLUGINS (13 Dedicated Detectors)   │  │
│  │    [HashSignature]  [PeStatic]      [DeepPe]         [Entropy]        │  │
│  │    [ScriptHeuristic][Authenticode]  [Persistence]    [LocationRep]    │  │
│  │    [ArchiveDetector][AntiEvasion]   [ProcessBehavior][MemoryBehavior] │  │
│  │    [NetworkBehavior]                                                  │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │ SecurityEvidence Items                │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ C. MULTI-SIGNAL RISK & CORRELATION ENGINE                             │  │
│  │    - RiskScoringEngine (Category Cap, Score Normalization 0-100)      │  │
│  │    - AttackChainCorrelator (60s Sliding Window MITRE Correlation)     │  │
│  │    - ProcessLineageTracker (Parent-Child Execution DAG)               │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │ DetectionResult & PolicyVerdict       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ D. RESPONSE & CONTAINMENT ENGINE                                      │  │
│  │    - QuarantineService (AES-256 DPAPI Atomic 6-Step Vault)            │  │
│  │    - ProcessTerminationService (Process tree kill)                    │  │
│  │    - NotificationAggregator (3-5s Batch Summary Toast Generator)      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Detection & Evidence Pipeline Flow

```
RAW FILE / PROCESS EVENT
          │
          ▼
1. CANONICALIZATION (PathHelper.CanonicalizePath, SHA-256, FileIdentity)
          │
          ▼
2. CONTENT-OVER-EXTENSION SNIFFING
   Sniffs first 4-16 bytes:
   - "MZ" (0x4D 0x5A) -> Native PE Binary
   - "PK" -> Zip / OpenXML Container
   - "7z" / "Rar!" -> Archive
   - Script Markers (#!, <script, powershell)
          │
          ▼
3. MULTI-LAYER CACHE LOOKUP (MultiLayerScanCache)
   - L1 Memory Cache (LRU <50µs)
   - L2 SQLite Cache (SHA256 + mtime + size)
   - If clean hit -> Immediate Return (Zero Disk I/O)
          │
          ▼ (Cache Miss)
4. DETECTIONHUB MULTI-PLUGIN EVALUATION
   - 13 Independent Plugins generate List<SecurityEvidence>
   - Authenticode verification (Digital Signature Risk Dampening)
          │
          ▼
5. SCORING & BEHAVIORAL CORRELATION
   - Category caps applied (Max 80 per category)
   - AttackChainCorrelator checks multi-stage sequence (60s window)
          │
          ▼
6. VERDICT & POLICY EXECUTION
   - RiskScore >= 85: ConfirmedMalicious -> Process Kill + DPAPI Quarantine
   - RiskScore 50-84: Suspicious -> Grouped Notification + Audit Log
   - RiskScore < 50:  Clean -> Allow & Cache
```

---

## 3. Kernel Subsystem Architecture (C Source in `drivers/`)

```
[ APPLICATION / MALWARE ]
            │
            ▼ (NTAPI NtCreateFile / NtWriteFile)
┌───────────────────────────────────────────────────────────────────────────┐
│ WINDOWS KERNEL (FLTMGR.SYS)                                               │
│                                                                           │
│  AegisFilter.sys (Minifilter Driver - C Source in drivers/)               │
│  - Pre-Create / Pre-Write Interception                                    │
│  - Stream Context Caching (FltSetFileContext)                             │
│  - FltSendMessage -> Holds I/O PENDING                                    │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │ Filter Communication Port
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ USER-MODE SECURITY SERVICE (AegisPC.Service)                              │
│                                                                           │
│  KernelIpcService (Worker Thread Pool)                                    │
│  - Receives File Handle / Path Buffer                                     │
│  - Passes to DetectionHub                                                 │
│  - FltReplyMessage -> GRANTED (Allow) or STATUS_ACCESS_DENIED (Block)     │
└───────────────────────────────────────────────────────────────────────────┘
```

> **Technical Reality Note:** The C Minifilter Driver source code exists in `drivers/` for security research. In the current release (v3.0), real-time protection is actively enforced via user-mode `FileSystemWatcher` and AMSI script gating.
