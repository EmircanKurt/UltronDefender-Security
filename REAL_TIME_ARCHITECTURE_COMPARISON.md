# ⚡ REAL-TIME PROTECTION ARCHITECTURE COMPARISON
**Document:** `REAL_TIME_ARCHITECTURE_COMPARISON.md`  
**Project:** Ultron Defender Total Security  
**Date:** 2026-08-19  

---

## 1. Interception Layers Analysis

In Windows endpoint security, real-time protection operates across several architectural layers:

```
[ USER-MODE APPLICATION / MALWARE ]
               │
               ▼  (Win32 / NTAPI File Write, Process Creation, Memory Alloc)
┌───────────────────────────────────────────────────────────────────────────┐
│ KERNEL-MODE                                                               │
│                                                                           │
│  1. Minifilter Driver (FltMgr) ────────► [ PRE-OP GATING ] ──► BLOCK I/O  │
│  2. Kernel Process Callbacks (PsSetCreateProcessNotifyRoutineEx) ────────┤
│  3. Kernel Object Callbacks (ObRegisterCallbacks) ────────────────────────┤
│  4. Kernel ETW Providers (Microsoft-Windows-Kernel-Process/File) ─────────┤
└───────────────────────────────────────────────────────────────────────────┘
               │  Filter Communication Port / Event Buffer / Pipe
               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ USER-MODE SERVICE (ULTRON DEFENDER SERVICE)                               │
│                                                                           │
│  5. AMSI Provider DLL ────────► In-Memory Script Interception             │
│  6. FileSystemWatcher / USN ──► Post-Op User-Mode Drop Zone Monitoring    │
│  7. DetectionHub (13 Plugins) ─► Multi-Signal Evidence & Scoring Engine   │
│  8. Response Coordinator ─────► DPAPI Quarantine / Process Kill           │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer-by-Layer Architectural Evaluation

| Interception Mechanism | Observes | Blocks (Gating) | Scans | Correlates | CPU / Latency | Limitations & Vulnerabilities |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **1. Kernel Minifilter Driver (`FLTMGR`)** | **YES** (All file I/O) | **YES (Pre-Op)** | Delegated to User-mode | Delegated to User-mode | Low (<100µs per file) | Requires EV Driver Signing or Test-Signing mode; Kernel bugs cause BSODs. |
| **2. Kernel Process Callbacks (`PsSet...`)** | **YES** (Process creation/exit)| **YES** (`CreationStatus = STATUS_ACCESS_DENIED`) | Delegated to User-mode | Delegated to User-mode | Ultra Low (<20µs) | Only covers process starts, not file writes. |
| **3. ETW (Event Tracing for Windows)** | **YES** (Rich system telemetry)| **NO (Post-Op only)** | User-mode | User-mode | Low-Medium | Events arrive asynchronously; malware can execute before user-mode receives ETW event. |
| **4. NTFS USN Journal** | **YES** (Volume file changes) | **NO (Post-Op only)** | User-mode | User-mode | Very Low | Polling-based or event-driven; no synchronous execution block. |
| **5. FileSystemWatcher (Win32)** | **YES** (Directory notifications)| **NO (Post-Op only)** | User-mode | User-mode | Low | Can drop events if buffer overflows during massive burst I/O; relies on user-mode APIs. |
| **6. AMSI (Antimalware Scan Interface)** | **YES** (PowerShell, VBS, JS) | **YES (Pre-Exec)** | User-mode (`amsi.dll`)| User-mode | Low (<2ms) | Only covers AMSI-instrumented runtimes (PowerShell, WScript, CScript, Office VBA). |

---

## 3. Ultron Defender Multi-Layer Strategy

1. **Active User-Mode Layer (Production Current):**
   * **Drop Zone Watchers:** High-frequency, debounced `FileSystemWatcher` across Desktop, Downloads, Temp, and Startup.
   * **Content-Over-Extension Engine:** Discovers disguised PEs immediately upon creation/rename.
   * **AMSI Real-Time Provider:** Synchronously blocks obfuscated PowerShell, VBScript, and JScript payloads in memory.
   * **Ransomware Mass-Write & Canary Guard:** Shuts down offending processes attempting rapid file modifications or honeypot tampering.
2. **Next-Phase Kernel Layer (Roadmap):**
   * **Minifilter Pre-Op Driver (`drivers/`):** Sends `IRP_MJ_CREATE` and `IRP_MJ_WRITE` to `KernelIpcService` for true pre-execution blocking.
