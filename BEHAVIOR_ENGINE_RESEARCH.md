# 🧬 BEHAVIOR ENGINE & ATTACK CHAIN CORRELATION RESEARCH
**Project:** Ultron Defender Total Security  
**Document:** `BEHAVIOR_ENGINE_RESEARCH.md`  
**Classification:** Behavioral Detection & Process Lineage  
**Date:** 2026-08-19  

---

## 1. Process Lineage & Soyağacı Graph Architecture

A process never acts in complete isolation. In modern endpoint attacks, initial staging occurs via an innocent-looking application (e.g. Word, Excel, Acrobat Reader, Chrome) which spawns LOLBins (Living-off-the-Land Binaries like `powershell.exe`, `cmd.exe`, `mshta.exe`, `certutil.exe`).

```
[ WINWORD.EXE (PID: 4012) ] ── (Office Document Macro)
            │
            ▼
[ POWERSHELL.EXE (PID: 5120) ] ── (Executes -enc <Base64>)
            │
            ▼
[ BITSADMIN.EXE (PID: 6240) ] ── (Downloads Second-Stage Stager)
            │
            ▼
[ UNKNOWN_STAGER.EXE (PID: 7890) ] ── (Drops in %TEMP% & Injects svchost)
```

`ProcessLineageTracker` constructs and maintains this directed acyclic graph (DAG) in memory, tracking:
* `ProcessNode`: PID, Parent PID, Image Path, Command Line, Start Time UTC, User Context, Integrity Level, Signer.
* `Ancestor Chain`: `GetAncestors(pid)` and `GetDescendants(pid)`.
* `Anomaly Detection`: Identifies Office/Browser spawning command interpreters or script hosts.

---

## 2. Multi-Stage Attack Chain Correlation (`AttackChainCorrelator`)

An attack unfolds over multiple chronological stages mapped to MITRE ATT&CK:

1. **Stage 1: Initial Execution & LOLBin Spawn** (e.g. `Office_Spawned_Interpreter`)
2. **Stage 2: Defense Evasion & AMSI Tampering** (e.g. `Obfuscated_Script_Execution`)
3. **Stage 3: Credential Access / Persistence** (e.g. `Browser_Credential_Harvesting` or `Registry_Run_Key`)
4. **Stage 4: C2 Communication & Exfiltration** (e.g. `Raw_IP_HTTPS_Beacon`)

When `AttackChainCorrelator` observes events spanning \(\ge 2\) MITRE stages within a 60-second sliding window for the same process tree, it automatically aggregates the weak signals into a high-confidence alert (\(Score \ge 85\)) and triggers automated containment.
