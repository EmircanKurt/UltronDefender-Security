# Windows Antimalware Architecture & Research Reference
## AegisPC / Ultron Defender Security Engineering

---

## 1. Microsoft Windows Antimalware Architecture (Official Standards)

### A. Windows File System Minifilter Architecture
* **Filter Manager (`FLTMGR.SYS`):** Windows kernel-mode subsystem that manages file system filter drivers.
* **Altitude Allocation:** Microsoft assigns specific altitude ranges (e.g., 320000-329999 for FSFilter Anti-Virus) ensuring AV filters load before activity monitors and virtualization filters.
* **Callback Model:**
  * `PreOperationCallback`: Intercepts file I/O requests (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_CLEANUP`, `IRP_MJ_SET_INFORMATION`) before file system processing. Allows returning `FLT_PREOP_COMPLETE` with `STATUS_ACCESS_DENIED` for immediate on-access blocking.
  * `PostOperationCallback`: Inspects buffers after successful read/creation (`IRP_MJ_CREATE`, `IRP_MJ_READ`).
* **Kernel-to-User IPC:** `FltCreateCommunicationPort` and `FilterConnectCommunicationPort` provide low-latency memory-shared message passing between kernel minifilter and user-mode scanning service.

### B. Antimalware Scan Interface (AMSI)
* **Standard:** Microsoft Win32 AMSI (`amsi.dll`) allows applications to integrate with the installed antimalware product.
* **Execution Flow:** Script hosts (PowerShell, VBScript, WScript, Office VBA, .NET CLR assembly loading) pass dynamic buffers to `AmsiScanString` / `AmsiScanBuffer` prior to JIT compilation and memory execution.
* **Result Codes:**
  * `AMSI_RESULT_CLEAN (0)`: No threat found.
  * `AMSI_RESULT_NOT_DETECTED (1)`: Scanner did not detect malicious pattern.
  * `AMSI_RESULT_BLOCKED_BY_ADMIN_START (16384)` - `(20479)`: Administrative block policy.
  * `AMSI_RESULT_DETECTED (32768)`: Malicious threat confirmed; script execution is aborted.

### C. Windows Security Center (WSC) & SecurityCenter2
* **WMI Provider:** `root\SecurityCenter2` namespace exposing `AntiVirusProduct` class.
* **State Bitmask (24-bit integer):**
  * `productState` (e.g. `0x041000` / `266240`):
    * High Byte (Bits 16-23): Product classification / signature provider.
    * Middle Byte (Bits 8-15): Scanner state (`0x10` = Real-time protection ON, `0x00` = OFF).
    * Low Byte (Bits 0-7): Definition state (`0x00` = Up to date, `0x10` = Outdated).

### D. Windows Filtering Platform (WFP)
* **Architecture:** In-kernel packet filtering subsystem managed by the Base Filtering Engine (`BFE`).
* **Layers:**
  * `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `V6`: Authorizes TCP connection attempts with process ID, path, and user identity.
  * `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4` / `V6`: Controls local port binding.
  * `FWPM_LAYER_DATAGRAM_DATA_V4` / `V6`: Inspects UDP/DNS datagram payloads.

### E. Early Launch Anti-Malware (ELAM) & Protected Process Light (PPL)
* **ELAM:** Microsoft-signed kernel driver initialized by the Windows Boot Manager before 3rd party drivers, classifying boot drivers as `KnownGood`, `KnownBad`, or `Unknown`.
* **PPL (Antimalware):** Prevents non-PPL administrative processes (even `NT AUTHORITY\SYSTEM` or local admin) from terminating the antimalware service using `OpenProcess(PROCESS_TERMINATE)`. Requires Microsoft Authenticode certificate with Antimalware EKU.

---

## 2. Research Citations & Official References

1. Microsoft Docs: *File System Minifilter Drivers* (https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/)
2. Microsoft Docs: *Antimalware Scan Interface (AMSI)* (https://learn.microsoft.com/en-us/windows/win32/amsi/)
3. Microsoft Docs: *Windows Filtering Platform Architecture* (https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview)
4. Microsoft Docs: *Protecting Anti-Malware Services (PPL)* (https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
5. MITRE ATT&CK Framework: *Enterprise Matrix - Persistence & Defense Evasion* (https://attack.mitre.org/)
6. EICAR Standard: *European Institute for Computer Antivirus Research Test File Specification* (https://www.eicar.org/)

---

## 3. AegisPC Architectural Positioning (Zero-Mock Reality)

| Component | Industry Standard (e.g. Defender/Bitdefender) | AegisPC Current Implementation | Reality Status |
| :--- | :--- | :--- | :--- |
| **File I/O Interception** | Kernel Minifilter (`FLTMGR.SYS` Pre-Op) | User-Mode 64KB `FileSystemWatcher` + Stability Poller | **USER-MODE (Ring 3)** |
| **Process Blocking** | Kernel `PsSetCreateProcessNotifyRoutineEx` | Win32 `Process.GetProcesses()` + PID Reuse Safe Killer | **USER-MODE (Ring 3)** |
| **Script Scanning** | In-Process AMSI Provider (`IAmsiProvider`) | Win32 `amsi.dll` P/Invoke + Local Script Heuristics | **VERIFIED (Ring 3)** |
| **Quarantine Vault** | Kernel-isolated encrypted container | AES-256-CBC with Windows DPAPI key protection | **VERIFIED (Ring 3)** |
| **Ransomware Defense** | Minifilter write velocity + shadow copy filter | Controlled Folders + Canary Decoys + Entropy Burst | **VERIFIED (Ring 3)** |
| **Network Protection** | Kernel WFP callout driver | Windows Hosts Sinkhole + DNS adapter enumerator | **PARTIAL (Ring 3)** |
| **Security Center** | WSC private COM + ELAM registration | WMI `root\SecurityCenter2` query + Registry Provider | **VERIFIED (Ring 3)** |
