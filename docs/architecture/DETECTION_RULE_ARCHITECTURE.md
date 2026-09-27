# 📐 DETECTION RULE ARCHITECTURE & CORRELATION ENGINE
**Project:** Ultron Defender Total Security  
**Document:** `DETECTION_RULE_ARCHITECTURE.md`  
**Classification:** Detection Engineering & Risk Calibration Blueprint  
**Date:** 2026-08-19  

---

## 1. Five-Level Detection Rule Hierarchy

A robust detection engine must not rely solely on simple single-event matching. Ultron Defender implements a **5-Level Detection Rule Hierarchy**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LEVEL 5: CONTEXTUAL CORRELATION                                             │
│ (Persistence + Browser Credential Access + Process Lineage Anomaly)        │
├─────────────────────────────────────────────────────────────────────────────┤
│ LEVEL 4: CROSS-DOMAIN CORRELATION                                           │
│ (Memory Injection Event + Outbound Raw IP Network Beacon)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│ LEVEL 3: AGGREGATE & THRESHOLD RULES                                        │
│ (>30 File Modifies in 2s with Entropy >7.85; 3+ Run Keys in 60s)           │
├─────────────────────────────────────────────────────────────────────────────┤
│ LEVEL 2: SEQUENCE & CHRONOLOGICAL CHAIN RULES                               │
│ (Office Document -> Spawns PowerShell -> Base64 Encoded Command)           │
├─────────────────────────────────────────────────────────────────────────────┤
│ LEVEL 1: ATOMIC & SINGLE-EVENT RULES                                        │
│ (Known Malicious SHA-256; vssadmin delete shadows; WH_KEYBOARD_LL hook)     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Rule Level Definitions & Specifications

### Level 1: Atomic Rules (Single Event)
* **Definition:** Pure pattern matching on a single incoming event without requiring historical context.
* **Examples:**
  * `Rule_L1_Known_Hash`: SHA-256 matches malware hash blocklist. (Score: +100)
  * `Rule_L1_ShadowCopy_Tampering`: Command line contains `delete shadows`. (Score: +75)
  * `Rule_L1_Unsigned_Sys_Driver`: Kernel driver dropped without WHQL signature. (Score: +60)

### Level 2: Sequence Rules (Chronological Multi-Event Chain)
* **Definition:** Matches a strict chronological sequence of events occurring within a defined time window \(T_{window}\).
* **Examples:**
  * `Rule_L2_LOLBin_Spawn`:
    1. Parent process is `WINWORD.EXE`, `EXCEL.EXE`, or `ACRORD32.EXE`.
    2. Spawns child process `POWERSHELL.EXE`, `CMD.EXE`, or `MSHTA.EXE` within \(T \le 5s\).
    3. Child executes with `-Enc` or `-ExecutionPolicy Bypass`.
    * **Calculated Score:** +85 (Confirmed Malicious).

### Level 3: Threshold & Aggregate Rules
* **Definition:** Evaluates the frequency or volumetric rate of events over a sliding time window.
* **Examples:**
  * `Rule_L3_Ransomware_Burst`:
    * \(\ge 30\) file write/rename events within \(2.0\) seconds.
    * Average file entropy delta \(\Delta H \ge 2.5\).
    * **Calculated Score:** +95 (Ransomware Burst Attack).
  * `Rule_L3_Rapid_Port_Scan`:
    * \(\ge 50\) failed TCP SYN attempts to distinct internal IPs within \(10\) seconds.
    * **Calculated Score:** +50 (Suspicious Reconnaissance).

### Level 4: Cross-Domain Correlation Rules
* **Definition:** Correlates disparate event domains (e.g. Memory + Network, or Registry + Filesystem).
* **Examples:**
  * `Rule_L4_Injected_C2_Beacon`:
    1. Process `svchost.exe` exhibits `PAGE_EXECUTE_READWRITE` unbacked memory section (Memory Domain).
    2. Process `svchost.exe` initiates outbound TLS connection to non-Microsoft IP (Network Domain).
    * **Calculated Score:** +90 (Memory Injected C2).

### Level 5: Contextual & Environmental Rules
* **Definition:** Combines low-level indicators with user context, file reputation, digital signatures, and directory trust.
* **Examples:**
  * `Rule_L5_Untrusted_Stealer_Chain`:
    1. Binary located in `%TEMP%` or `%APPDATA%` without valid signature.
    2. Reads Chrome/Edge credential stores.
    3. Writes staging archive to `%TEMP%`.
    4. Initiates outbound network connection.
    * **Calculated Score:** +95.

---

## 3. Time-Aware Sliding Window Architecture

Correlation windows are tailored to the operational dynamics of each threat behavior:

| Behavior Category | Sliding Window Duration | Retention Policy | Memory Footprint Cap |
| :--- | :---: | :--- | :--- |
| **Process Injection (Hollowing / APC)** | **5 seconds** | Ring Buffer (Last 256 events) | 2 MB per Process Tree |
| **Ransomware Mass Modification** | **2 seconds** | High-precision tick queue | 1 MB per Volume |
| **Credential Stealing & Staging** | **30 seconds** | Event Map | 5 MB |
| **Keylogger Input Accumulation** | **5 minutes** | Aggregated Counter | 500 KB |
| **RAT / C2 Persistent Beaconing** | **30 minutes** | Statistical Jitter Histogram | 4 MB |

---

## 4. Risk Scoring & Calibration Model

Risk scores are not calculated by simple unbounded arithmetic addition. Unbounded summation causes alert fatigue from cumulative benign noise.

### Mathematical Formulation:
Let each active evidence \(e_i\) have:
* Base Score Contribution \(S_i \in [0, 100]\)
* Evidence Confidence \(C_i \in [0.0, 1.0]\)
* Domain Category \(K(e_i)\) with category cap \(M_k\)

For each domain category \(k\):
\[
Score_k = \min\left( M_k, \sum_{e_i \in K_k} S_i \times C_i \right)
\]

Total Correlated Risk Score \(R_{total}\):
\[
R_{total} = \min\left( 100, \sum_k Score_k \times W_k \times \Phi_{sig} \right)
\]
Where \(\Phi_{sig}\) is the Digital Signature Modifier:
* \(\Phi_{sig} = 1.00\) (Unsigned / Invalid Signature)
* \(\Phi_{sig} = 0.85\) (Valid Third-Party Commercial Signature)
* \(\Phi_{sig} = 0.40\) (Valid Microsoft Windows WHQL Signature — unless Live Injection or Tampering is confirmed)

---

## 5. Static / Behavioral Agreement Matrix

| Static Verdict (File / PE / YARA) | Behavioral Verdict (Lineage / Runtime) | Final Action (Policy) | User Notification Mode |
| :--- | :--- | :--- | :--- |
| **Clean (Score < 30)** | **Clean (Score < 30)** | **ALLOW** | Silent (No notification) |
| **Clean (Score < 30)** | **Suspicious (Score 50–69)** | **OBSERVE & LOG** | Audit Log only |
| **Clean (Score < 30)** | **Confirmed Malicious (Score \(\ge 85\))** | **CONTAIN & KILL** *(Behavior Overrides Static)* | Immediate Critical Alert |
| **Suspicious (Score 50–69)** | **Clean (Score < 30)** | **ALLOW / WARN** | Grouped Toast Notification |
| **Suspicious (Score 50–69)** | **Suspicious (Score 50–69)** | **QUARANTINE** *(Combined Risk \(\ge 80\))*| Grouped Toast Notification |
| **Confirmed Malicious (\(\ge 85\))**| **Clean (Not yet executing)** | **PRE-EXECUTION QUARANTINE** | Grouped Toast Notification |
| **Confirmed Malicious (\(\ge 85\))**| **Confirmed Malicious (\(\ge 85\))** | **IMMEDIATE KILL & ATOMIC VAULT** | Immediate Critical Alert |
