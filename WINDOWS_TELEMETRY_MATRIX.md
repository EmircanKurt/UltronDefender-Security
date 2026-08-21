# 📡 WINDOWS TELEMETRY MATRIX — DEFENSIVE SENSOR EVALUATION
**Project:** Ultron Defender Total Security  
**Classification:** Defensive Telemetry Engineering  
**Date:** 2026-08-19  

---

## 1. Executive Telemetry Overview

A production-grade Windows EDR/AV cannot rely on a single data source. Real-time protection requires a layered sensor architecture spanning Kernel Callbacks, File System Minifilters, Event Tracing for Windows (ETW), Antimalware Scan Interface (AMSI), and Win32 User-Mode APIs.

---

## 2. Sensor Evaluation Matrix

| Telemetry Sensor | Primary Signals Observed | Blind Spots / What It Cannot Observe | Latency | Reliability | Execution Gating (Pre-Op Blocking) | Required Privilege | Performance Cost | Security Boundary / Bypass Risk |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Kernel Minifilter (`FLTMGR`)** | File Create, Read, Write, Rename, Delete, SetInfo, Directory Enum, Alternate Data Streams (`:Zone.Identifier`). | In-memory code execution without disk writes; direct memory injection. | `< 50 µs` | **100% (Kernel)** | **YES (`STATUS_ACCESS_DENIED`)** | Kernel-Mode Driver (Ring 0, EV/Test Sign) | Very Low with Context Cache | Cannot be bypassed from User-mode without Bring-Your-Own-Vulnerable-Driver (BYOVD). |
| **Kernel Process Callbacks (`PsSetCreateProcessNotifyRoutineEx`)** | New process creation, parent PID, creator PID/TID, command line, image file name. | Process hollowing after creation; thread creation inside existing process. | `< 10 µs` | **100% (Kernel)** | **YES (`CreationStatus = STATUS_ACCESS_DENIED`)** | Kernel-Mode Driver (Ring 0) | Negligible | Ring 0 callback cannot be unhooked from Ring 3. |
| **Kernel Thread Callbacks (`PsSetCreateThreadNotifyRoutine`)** | New thread creation, target process ID, thread start address. | In-thread shellcode execution; APC queue execution without new thread. | `< 10 µs` | **100% (Kernel)** | **NO** (Post-notify) | Kernel-Mode Driver (Ring 0) | Low | Ring 0 callback. |
| **Kernel Image Load Callbacks (`PsSetLoadImageNotifyRoutine`)** | DLL / Module loading, driver loading, mapped image base and size. | Manual DLL mapping (`Reflective DLL Injection`, memory-only PE loaders). | `< 20 µs` | **100% (Kernel)** | **NO** (Post-notify) | Kernel-Mode Driver (Ring 0) | Low | Ring 0 callback. |
| **Object Callbacks (`ObRegisterCallbacks`)** | Process / Thread handle creation (`OpenProcess`), requested access mask (`PROCESS_VM_WRITE`, `PROCESS_TERMINATE`). | In-process execution without cross-process handle opening. | `< 15 µs` | **100% (Kernel)** | **YES** (Access mask strip: removes `PROCESS_VM_WRITE`) | Kernel-Mode Driver (Ring 0) | Low | Prevents LSASS dumping and self-process termination. |
| **AMSI (`amsi.dll` / Antimalware Scan Interface)** | Obfuscated PowerShell, VBScript, JScript, Office VBA Macros, WMI script buffers, .NET assembly loads. | Pure compiled C/C++ native binaries; direct syscall execution. | `< 2 ms` | **High** | **YES** (`AMSI_RESULT_DETECTED` blocks execution) | User-Mode Service / AMSI Provider DLL | Low | AMSI memory patch (`amsi.dll!AmsiScanBuffer` return `AMSI_RESULT_CLEAN`) if process unmonitored. |
| **ETW (`Microsoft-Windows-Kernel-Process` / `Threat-Intelligence`)** | Process start, RPC calls, virtual memory alloc (`PAGE_EXECUTE_READWRITE`), section map, token elevation. | Asynchronous delivery delay (10ms–500ms); dropped events on high load. | `10–200 ms` | **Medium-High** | **NO** (Telemetry only, no gating) | Administrator / `NT AUTHORITY\SYSTEM` | Low | User-mode ETW patching (`ntdll!EtwEventWrite` RET) can blind userland ETW consumers. |
| **Windows Filtering Platform (WFP)** | Outbound/Inbound TCP/UDP, DNS queries, socket binds, PID-to-IP correlation. | Raw packet crafting bypassing NDIS; intra-process IPC. | `< 30 µs` | **High** | **YES** (`FWP_ACTION_BLOCK`) | Kernel Driver / Admin API (`FwpmFilterAdd0`) | Very Low | Kernel filtering. |
| **NTFS USN Change Journal** | Historical file creations, modifications, deletions, renames across NTFS volumes. | File contents; process attributing the change; memory-only changes. | `Polling / Stream` | **High (Disk)** | **NO** (Post-write journal) | Administrator / Read Volume Handle | Ultra Low | Journal can be cleared (`fsutil usn deletejournal`). |
| **Win32 `FileSystemWatcher`** | User drop-zone directory changes (Desktop, Downloads, Temp, Startup). | Kernel pre-op interception; locked file contents during early write. | `50–500 ms` | **Medium** (Buffer overflow on burst) | **NO** (Post-creation) | User-Mode (Standard / Admin) | Low | Debouncing required; buffer overflows if >1000 events fire concurrently. |
| **Windows Event Log (Security / Sysmon)** | Event IDs 4688 (Process Create), 4624 (Logon), 7045 (Service Install), 1102 (Log Cleared). | Real-time low-latency response; fine-grained memory/API activity. | `100–1000 ms` | **High** | **NO** (Log only) | EventLog Readers / Admin | Medium | Event Log service tampering; log flooding. |

---

## 3. Ultron Telemetry Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. TELEMETRY INGESTION                                                     │
│    - File Drop Zones: FileSystemWatcher (Desktop, Downloads, Temp, Startup) │
│    - Memory / Script Execution: Win32 AMSI Provider Interface               │
│    - Process Lifecycle: ProcessMonitorService (Win32 Toolhelp32 / WMI / ETW)│
│    - File I/O Gating: Minifilter Driver (C Source in drivers/ + IPC Port)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. TELEMETRY NORMALIZATION                                                 │
│    Raw Windows Event ──► CanonicalPath ──► SHA256 ──► Signer ──► ProcessNode│
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. MULTI-SIGNAL EVALUATION (DetectionHub - 13 Modular Plugins)             │
│    [PE Static] [DeepPE] [Entropy] [Authenticode] [Persistence] [AMSI] ...   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. BEHAVIORAL CORRELATION (AttackChainCorrelator & LineageTracker)         │
│    Sequence Matching (60s window) ──► Weak-Signal Aggregation ──► RiskScore │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. RESPONSE COORDINATION                                                    │
│    - Score >= 85: ProcessTree Termination + DPAPI Atomic Quarantine         │
│    - Score 50–84: Warning / NotificationAggregator Batch Alert              │
│    - Score < 50: Allow & Audit Log Record                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```
