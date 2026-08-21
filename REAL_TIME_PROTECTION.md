# Real-Time Protection Engine: Technical Architecture & Limitations
## AegisPC / Ultron Defender Security Engineering

---

## 1. Pipeline Overview (User-Mode File Arrival Engine)

```
[OS File System Event (Created / Modified / Renamed)]
                        │
                        ▼
            [64KB FileSystemWatcher]
                        │
                        ▼
              [Bounded Event Channel]
                        │
                        ▼
            [WaitForFileStabilityAsync]
       (Polling size stability & FileShare lock)
                        │
                        ▼
              [InspectFileAsync]
 ├── STAGE 1: Fast Hash & Signature DB (O(1))
 ├── STAGE 2: Win32 Authenticode Digital Signature
 ├── STAGE 3: PE Header & Shannon Entropy Analysis
 └── STAGE 4: Static Pattern Matching (Keylogger, Dropper, EICAR)
                        │
                        ▼
                [Policy Evaluation]
 ├── ConfirmedMalicious / HighRisk (Score >= 70) ──► BlockAndQuarantine
 ├── Suspicious (Score 40..69) ───────────────────► Warn (User Alert, Never Delete)
 └── Clean / Unknown (Score < 40) ────────────────► Allow (Untouched on disk)
                        │
                        ▼
             [Action & Telemetry Logging]
 ├── Terminate running process tree if executing
 ├── Encrypt & move to AES-256 Vault (.quar)
 ├── Zero-wipe and delete original file from disk
 └── Log Time-to-Detect (TTD) & Time-to-Action (TTA)
```

---

## 2. FileSystemWatcher Limitations (Why Real-Time Protection is PARTIAL)

User-mode `FileSystemWatcher` has inherent architectural constraints when compared to a native kernel minifilter:

1. **Post-Operation Only (No Pre-Operation Interception):** `FileSystemWatcher` receives notifications *after* the file has already been created or written to disk by the Windows I/O manager. A kernel minifilter (`FLTMGR.SYS`), by contrast, intercepts `IRP_MJ_CREATE` *before* disk write and can return `STATUS_ACCESS_DENIED`.
2. **TOCTOU Race Condition (Time-of-Check to Time-of-Use):** If a user downloads a malicious `.exe` and immediately double-clicks it within milliseconds, the process can start executing before `WaitForFileStabilityAsync` finishes scanning. (AegisPC mitigates this via its active process tree killer upon verdict).
3. **Buffer Overflow on High Event Volume:** Under extreme I/O bursts (>5,000 files/sec), the 64KB internal buffer can overflow, causing `Error` events and potential missed notifications.
4. **Temporary Download Renames (`.crdownload` / `.tmp`):** Browsers download to temporary extensions before an atomic rename. While `Renamed` is monitored, debouncing can cause minor latency.
5. **Network & Virtual Drives:** UNC paths and disconnected network shares do not reliably raise `FileSystemWatcher` events.
6. **Kernel-Level Rootkits:** A Ring 0 rootkit can hook `NtQueryDirectoryFile` or filesystem drivers to completely bypass user-mode `FileSystemWatcher`.

---

## 3. Comparison with Windows Defender (Real Architecture)

| Component | Microsoft Windows Defender (`MsMpEng.exe`) | AegisPC / Ultron Defender | Honest Assessment |
| :--- | :--- | :--- | :--- |
| **File System Hook** | Kernel Minifilter (`WdFilter.sys`, Altitude `328010`) | User-Mode 64KB `FileSystemWatcher` | **Defender Superior** (True Pre-op blocking vs Post-op notification) |
| **Process Interception** | Kernel Callbacks (`PsSetCreateProcessNotifyRoutineEx`) | User-Mode Process Enumeration + PID Reuse Killer | **Defender Superior** (Blocks before thread start vs Post-start kill) |
| **Script Inspection** | Registered In-Process AMSI Provider (`MpOAv.dll`) | Win32 `amsi.dll` P/Invoke + Local Heuristics | **Comparable for script scanning** |
| **Network Inspection** | Kernel WFP Driver (`WdFilter.sys` ALE layers) | Windows Hosts Sinkhole + Adapter Reader | **Defender Superior** (Raw TLS/IP filtering vs DNS sinkhole) |
| **Cloud Intelligence** | Microsoft MAPS (Billions of real-time signatures) | Offline Hash/Signature Dictionary | **Defender Superior** (Cloud scale vs Local privacy) |
| **Quarantine Vault** | Windows Defender Quarantine Encrypted Container | AES-256-CBC DPAPI Encrypted Vault (`.quar`) | **Equivalent cryptographic security** |
| **Ransomware Defense** | Controlled Folder Access + Shadow Copy Protection | Controlled Folders + Canary Decoys + Burst Velocity | **Comparable heuristic decoy detection** |
