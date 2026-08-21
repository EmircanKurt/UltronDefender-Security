# 🛡️ DEFENSIVE ANTI-EVASION & ANTI-ANALYSIS RESEARCH
**Project:** Ultron Defender Total Security  
**Document:** `ANTIEVASION_RESEARCH.md`  
**Classification:** Defensive Evasion Analysis & Detection Engineering  
**Date:** 2026-08-19  

---

## 1. Defensive Objective

Advanced malware employs anti-analysis, anti-debugging, and EDR-evasion techniques to conceal itself from static scanners and user-mode API hooks. **The defensive goal is to detect the act of evasion itself as a high-confidence indicator of malicious intent.**

---

## 2. Evasion Technique & Defensive Detection Matrix

| Evasion Technique | Mechanism (What Malware Does) | Observable Defensive Telemetry | Ultron Detection Strategy | Required Sensor |
| :--- | :--- | :--- | :--- | :--- |
| **AMSI In-Memory Patching** | Overwrites `amsi.dll!AmsiScanBuffer` with `mov eax, 0x80070057; ret` (`0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3`) to force clean return. | Memory page protection of `amsi.dll` `.text` section modified to `PAGE_EXECUTE_READWRITE`; first 6 bytes corrupted. | Periodic integrity check on loaded `amsi.dll` exported functions; memory scanner flags modified function preludes. | MemoryPatternScanner / AmsiScanService |
| **ETW User-Mode Blinding** | Overwrites `ntdll.dll!EtwEventWrite` with `ret` (`0xC3`) or `xor eax, eax; ret` (`0x31, 0xC0, 0xC3`) to mute telemetry. | Protection change on `ntdll.dll` text section; bytes at `EtwEventWrite` do not match original image on disk. | Verify `ntdll.dll` function prelude integrity against clean disk image; flag write attempts to `ntdll.dll` text section. | AntiEvasionDetector / ProcessMonitor |
| **Indirect Syscalls (Hell's Gate / Halo's Gate / Tartarus)** | Manually copies syscall number into `EAX` and jumps to `syscall` / `sysenter` opcode inside `ntdll.dll` to bypass user-mode hooks. | Execution stack trace shows kernel transition without standard `ntdll.dll` wrapper frame; thread instruction pointer points to dynamically allocated memory. | Stack unwinding validation; memory scanner detects indirect syscall stubs (`4C 8B D1 B8 [SSN] 00 00 0F 05 C3`). | AntiEvasionDetectorPlugin |
| **API Unhooking (FreshyCalls / Perun's Fart)** | Reads clean copy of `ntdll.dll` from disk (`\KnownDlls\ntdll.dll` or `C:\Windows\System32\ntdll.dll`) and overwrites active `.text` section. | Section re-mapping or `VirtualProtect(PAGE_EXECUTE_READWRITE)` on `ntdll.dll` followed by disk read of system DLLs. | Monitor file reads of `\System32\ntdll.dll` by non-system processes accompanied by memory protection changes. | ProcessMonitor / AntiEvasionDetector |
| **Process Hollowing / RunPE** | Spawns suspended target (e.g. `svchost.exe`), unmaps section (`NtUnmapViewOfSection`), allocates RWX, writes payload, resumes. | Suspended process start + cross-process memory allocation + PE header overwrite + thread start address mismatch. | `ProcessInjectionDetector` verifies PE header integrity and compares thread entry point to on-disk PE entry point. | ProcessInjectionDetector |
| **Thread Context Hijacking** | Suspends remote thread (`SuspendThread`), modifies `RIP`/`EIP` via `SetThreadContext` to point to shellcode, resumes. | Cross-process thread open with `THREAD_SET_CONTEXT` + `THREAD_SUSPEND_RESUME` privileges. | Object handle monitoring + remote thread context inspection. | ProcessInjectionDetector |
| **Early Bird APC Injection** | Creates process in suspended state, queues user-mode APC (`QueueUserAPC`) before main thread initializes, resumes. | `QueueUserAPC` called on newly created suspended process with target address in unbacked private memory. | Intercept `QueueUserAPC` targeting non-module memory during process initialization phase. | ProcessInjectionDetector |
| **Anti-VM & Sandbox Artifact Probing** | Queries Registry keys (e.g. `HARDWARE\Description\System\SystemBiosVersion` containing `VBOX`, `VMware`, `QEMU`), checks hypervisor bit via `CPUID`, checks uptime (`GetTickCount64 < 10 mins`), checks screen resolution. | High burst of hardware/hypervisor registry queries in first 100ms of process startup without user GUI interaction. | Detect rapid sequence of hypervisor environment checks in unknown unsigned binaries. | PeStaticDetector / BehaviorEngine |
| **Anti-Debugging (PEB / IsDebuggerPresent / NtQueryInformationProcess)** | Checks `BeingDebugged` flag in PEB (`fs:[0x30]` / `gs:[0x60]`), calls `CheckRemoteDebuggerPresent`, checks `NtGlobalFlag` (`0x70`), invokes `NtQueryInformationProcess(ProcessDebugPort)`. | Direct access to PEB flags combined with API queries. | Static PE scanner detects anti-debug imports; runtime engine monitors debugging check patterns. | PeStaticDetector / DeepPeAnalyzer |

---

## 3. Defensive Engineering Guidelines

1. **Avoid Reliance on In-Process Userland Hooks Alone:** Userland API hooks in `ntdll.dll` can be bypassed by unhooking or indirect syscalls. Ultron relies primarily on Kernel Callbacks, AMSI, ETW, and Independent Memory Scanners.
2. **Treat Evasion Detection as High-Severity Evidence:** Legitimate business software does not patch `amsi.dll` or unhook `ntdll.dll`. The detection of AMSI patching or Indirect Syscall stubs yields an automatic high evidence score (+75 to +85).
3. **Memory Integrity Scanners:** Regularly scan loaded module `.text` sections against disk counterparts to detect in-memory tampering and hook removal.
