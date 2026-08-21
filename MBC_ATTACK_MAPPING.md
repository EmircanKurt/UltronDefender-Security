# 🗺️ MBC & MITRE ATT&CK TO WINDOWS TELEMETRY MAPPING
**Project:** Ultron Defender Total Security  
**Document:** `MBC_ATTACK_MAPPING.md`  
**Classification:** Defensive Knowledge Graph  
**Date:** 2026-08-19  

---

## 1. Architectural Philosophy: Metadata vs. Evidence

> **Core Axiom:** A MITRE ATT&CK ID (e.g. `T1056.001`) or MBC Behavior ID (e.g. `B0015`) is **metadata**, not detection evidence. True detection evidence must originate from concrete, observable Windows telemetry (Win32 API calls, kernel callbacks, memory states, filesystem operations, and network packets).

---

## 2. Comprehensive ATT&CK / MBC Telemetry Mapping

| ATT&CK ID | ATT&CK Technique Name | MBC Behavior | Concrete Observable Windows Signal | Ultron Telemetry Source | Ultron `SecurityEvidence` Rule | Risk Contribution | Response Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **T1056.001** | Input Capture: Keylogging | `B0015` (Keylogging) | `SetWindowsHookExW(WH_KEYBOARD_LL)` or polling `GetAsyncKeyState` without focused UI window. | Win32 Hook Scanner / DetectionHub | `Rule_Keylogger_Hook_Detected` | **+40** | Tag for keylogger correlation; inspect log drops. |
| **T1055.012** | Process Injection: Process Hollowing | `B0046` (Process Hollowing) | `CreateProcess(CREATE_SUSPENDED)` + `NtUnmapViewOfSection` / `VirtualAllocEx(RWX)` + `WriteProcessMemory` + `ResumeThread`. | ProcessInjectionDetector | `Rule_Process_Hollowing_Sequence` | **+85** | Immediate child process kill + parent containment. |
| **T1055.004** | Process Injection: Asynchronous Procedure Call (APC) | `B0045` (APC Injection) | `QueueUserAPC` targeting `svchost.exe` / `explorer.exe` with address pointing to unbacked memory. | ProcessInjectionDetector | `Rule_EarlyBird_APC_Injection` | **+80** | Suspend thread + terminate injector. |
| **T1486** | Data Encrypted for Impact (Ransomware) | `B0032` (File Encryption) | >30 file writes/s, extension replacement, Shannon entropy surge (>7.85), Canary file modification. | RansomwareProtectionEngine | `Rule_Ransomware_Mass_Write_Burst` | **+90** | Immediate process tree kill + alert + quarantine. |
| **T1490** | Inhibit System Recovery | `B0031` (System Recovery Tampering) | Execution of `vssadmin.exe delete shadows` or `bcdedit.exe /set {default} recoveryenabled No`. | ScriptHeuristicDetector / Lineage | `Rule_ShadowCopy_Deletion_Attempt` | **+75** | Kill child process + block command execution. |
| **T1555.003** | Credentials from Web Browsers | `B0013` (Credential Stealing) | Direct read of `Login Data`, `Web Data`, `Cookies` sqlite DB by non-browser unsigned process. | BehaviorEngine / DetectionHub | `Rule_Browser_Credential_Harvesting` | **+70** | Block file access + correlate with network POST. |
| **T1547.001** | Boot/Logon Autostart: Registry Run Keys | `B0025` (Persistence via Run) | Registry write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` referencing AppData/Temp binary. | PersistenceDetector | `Rule_Suspicious_RunKey_Persistence` | **+45** | Remove registry value + inspect payload. |
| **T1053.005** | Scheduled Task | `B0026` (Task Scheduler) | `schtasks.exe /create /tn ... /tr ...` spawned by script or downloaded binary. | PersistenceDetector | `Rule_Scheduled_Task_Persistence` | **+40** | Audit task + inspect target binary. |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | `B0038` (Script Execution) | `powershell.exe -enc <Base64>` or `-ExecutionPolicy Bypass -WindowStyle Hidden -w hidden`. | ScriptHeuristicDetector / AMSI | `Rule_Obfuscated_PowerShell_Execution`| **+55** | Pass buffer to AMSI + inspect lineage. |
| **T1140** | Deobfuscate / Decode Files or Information | `B0028` (Payload Deobfuscation)| In-memory base64 decode followed by `Assembly.Load` or `VirtualAlloc(PAGE_EXECUTE_READWRITE)`. | AMSI / MemoryDetector | `Rule_In_Memory_Payload_Deobfuscation`| **+60** | Memory scan + quarantine source. |
| **T1027.007** | Obfuscated Files: Dynamic API Resolution | `B0024` (Dynamic Resolving) | PE binary import table lacks Win32 APIs, but calls `GetProcAddress` / `LoadLibraryA` on hundreds of functions. | PeStaticDetector / DeepPeAnalyzer | `Rule_Dynamic_API_Resolving_High_Count`| **+35** | Add static heuristic score + monitor runtime. |
| **T1071.001** | Application Layer Protocol: Web Protocols | `B0010` (C2 Communication) | Outbound HTTP POST to raw IP address / Dynamic DNS without User-Agent header or with suspicious stager URI. | NetworkBehaviorDetector | `Rule_Suspicious_Raw_IP_C2_Beacon` | **+45** | Correlate with process lineage + alert. |
| **T1562.001** | Impair Defenses: Disable Tools | `B0006` (Defense Impairment) | Modifying `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` or attempting to stop security services. | BehaviorEngine / SafetyGuard | `Rule_Security_Product_Tampering` | **+85** | Rollback registry edit + isolate process. |

---

## 3. End-to-End Defensive Knowledge Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. THREAT ACTOR ACTIVITY                                                    │
│    Malware: Lumma Stealer                                                   │
│    Action: Reads Chrome Login Data -> Writes %TEMP%\out.zip -> Posts to C2  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. WINDOWS TELEMETRY SENSORS                                                │
│    - File I/O: Read on AppData\Local\Google\Chrome\User Data\...\Login Data │
│    - File I/O: Create & Write on %TEMP%\out.zip (PK magic bytes)            │
│    - Network: Socket connect & TLS POST to 194.87.x.x:443                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. ULTRON DETECTION EVIDENCE AGGREGATION                                    │
│    - Evidence 1: Rule_Browser_Credential_Harvesting (Score: +70)            │
│    - Evidence 2: Rule_Suspicious_Staging_Archive (Score: +30)               │
│    - Evidence 3: Rule_Suspicious_Raw_IP_C2_Beacon (Score: +45)              │
│    - Category Cap: CredentialAccess (Max: 80), Exfiltration (Max: 70)      │
│    - Total Correlated Score: 95 (Confirmed Malicious)                       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. DEFENSIVE REMEDIATION                                                    │
│    - Process Tree Terminated: Offending PID & children killed immediately   │
│    - File Quarantined: Source binary & staging archive encrypted in DPAPI   │
│    - Telemetry Logged: Incident recorded with MITRE T1555.003 & MBC B0013   │
│    - User Notified: Grouped Toast notification displayed to user            │
└─────────────────────────────────────────────────────────────────────────────┘
```
