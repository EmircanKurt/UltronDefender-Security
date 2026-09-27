# 🧠 DEFENSIVE IN-MEMORY THREAT DETECTION RESEARCH
**Project:** Ultron Defender Total Security  
**Document:** `MEMORY_DETECTION_RESEARCH.md`  
**Classification:** Memory Forensics & Injection Defense  
**Date:** 2026-08-19  

---

## 1. Defensive Memory Analysis Principles

Fileless malware and advanced loaders (e.g. Cobalt Strike Beacon, Meterpreter, reflective loaders) evade disk-based scanners by executing entirely in memory. **Ultron Defender employs defensive memory scanning to detect in-memory payloads without requiring dangerous userland hooks.**

---

## 2. In-Memory Indicator Matrix

| Memory Indicator | Win32 / NTAPI Representation | Detection Significance | Ultron Detector |
| :--- | :--- | :--- | :--- |
| **Unbacked Executable Memory (`MEM_PRIVATE` + `PAGE_EXECUTE_...`)** | Virtual memory allocated via `VirtualAlloc` without being mapped to an on-disk image file (`MEM_IMAGE`). | Highly anomalous in standard processes; indicates injected shellcode, stagers, or unpacked PEs. | `MemoryPatternScanner` / `MemoryBehaviorDetector` |
| **`PAGE_EXECUTE_READWRITE` (W+X) Transitions** | Memory page allocated as `PAGE_READWRITE` (0x04) and subsequently changed to `PAGE_EXECUTE_READWRITE` (0x40) or `PAGE_EXECUTE_READ` (0x20). | Signature pattern of shellcode decoders and JIT compiler hooks. | `ProcessInjectionDetector` |
| **Hollowed PE Header in Legitimate Process** | Memory inspection of a system process (e.g. `svchost.exe`) reveals a secondary `MZ`/`PE` header in private memory or modified original image header. | Strong confirmation of Process Hollowing / RunPE. | `ProcessInjectionDetector` |
| **Cobalt Strike / Meterpreter Stager Signatures** | Specific byte patterns in unbacked memory: `\xFC\x48\x83\xE4\xF0` (x64 shellcode prelude) or indirect syscall stubs. | High-confidence C2 stager detection. | `MemoryPatternScanner` |
| **Suspicious Cross-Process Handle Rights** | Process handles opened with `PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD`. | Precursor to remote thread injection. | `ProcessInjectionDetector` |

---

## 3. Defensive Memory Scan Workflow

1. **Target Selection:** Priority given to unsigned processes, processes running from Temp/AppData, and system processes with abnormal child lineages.
2. **Page Enumeration:** Iterates memory regions using `VirtualQueryEx`.
3. **Filter:** Inspects only `MEM_COMMIT` regions with `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, or `PAGE_EXECUTE_READWRITE`.
4. **Pattern Sniffing:** Scans the first 4KB of each candidate memory region for PE signatures, reflective loader stubs, or shellcode preludes.
5. **Containment:** If confirmed malicious memory payload is found, the process is terminated immediately.
