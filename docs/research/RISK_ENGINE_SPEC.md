# 📐 ULTRON DEFENDER TOTAL SECURITY — RISK SCORING ENGINE MATHEMATICAL SPECIFICATION

**Document:** `RISK_ENGINE_SPEC.md`  
**Classification:** Core Algorithm & Detection Math Specification  
**Version:** 3.0.0-Unified  
**Date:** 2026-08-20  

---

## 1. Mathematical Architecture & Transformation Pipeline

The Ultron Defender Risk Engine transforms discrete detector evidence into an explainable, deterministic risk score \(S_{final} \in [0, 100]\).

```
 [ Detector Plugins (13 Independent Sensors) ]
                      │
                      ▼
 [ 1. Rule-Level Deduplication (Unique Rule + FilePath) ]
                      │
                      ▼
 [ 2. Correlation Group Aggregation (Dominant Signal + Corroboration Bonus) ]
                      │
                      ▼
 [ 3. Category Score Capping (Hard Upper Boundary per Category) ]
                      │
                      ▼
 [ 4. Context Trust Modifier (Digital Signature & Path Validation) ]
                      │
                      ▼
 [ 5. Mathematical Clamping & Score Trace Generation ]
```

---

## 2. Formal Mathematical Definition

Let \(E = \{e_1, e_2, \dots, e_n\}\) be the set of unique security evidences extracted from a file or process.

Each evidence \(e_i\) has:
* Rule Identifier \(R_i\)
* Score Contribution \(s_i \in \mathbb{Z}^+\)
* Evidence Category \(C_i \in \mathcal{C}\)
* Correlation Group \(G_i \in \mathcal{G}\) (e.g. `Packing`, `DigitalSignature`, `PeStructure`, `ProcessLineage`)
* Confidence \(c_i \in [0.1, 1.0]\)

---

### Step 1: Correlation Group Deduplication
When multiple detectors observe the same physical phenomenon (e.g. high file entropy + section `.rsrc` entropy + packer markers), they belong to the same group \(G_k\).

The effective group score \(S(G_k)\) is computed as:
\[
S(G_k) = \max_{e \in G_k}(s_e) + \left\lfloor \frac{\sum_{e \in G_k \setminus \{e_{max}\}} s_e}{4} \right\rfloor
\]
* **Dominant Signal:** Receives 100% weight.
* **Corroborating Signals:** Receive a 25% corroboration bonus (\(\frac{1}{4}\)), preventing score inflation.

---

### Step 2: Category Score Capping
Each category \(K \in \mathcal{C}\) enforces a hard upper cap \(M_K\):

| Evidence Category | Hard Cap (\(M_K\)) | Rationale |
| :--- | :---: | :--- |
| **`StaticSignature`** | **100** | Exact SHA-256 or YARA byte pattern match is definitive. |
| **`AntiEvasion`** | **80** | Memory patching, direct syscalls, AMSI patch indicators. |
| **`BehaviorProcess`**| **60** | Process hollowing, child process spawning from Office. |
| **`BehaviorMemory`** | **50** | `VirtualAllocEx` + `WriteProcessMemory` remote injection. |
| **`ScriptHeuristic`** | **50** | Obfuscated PowerShell, shadow copy deletion script. |
| **`StaticApi`** | **45** | Keylogger APIs (`SetWindowsHookEx`, `GetAsyncKeyState`). |
| **`StaticPeStructure`**| **40** | Suspicious PE headers, TLS callbacks, abnormal section counts. |
| **`ArchiveAnomaly`** | **40** | High compression ratios (>100:1), deep nesting (>4). |
| **`EntropyAnomaly`** | **35** | High Shannon entropy (>7.85) indicating crypters/compression. |
| **`LocationReputation`**| **35** | Execution from `%TEMP%` or hidden drop zones. |
| **`Persistence`** | **30** | Run keys, scheduled tasks, startup folder persistence. |
| **`BehaviorNetwork`**| **30** | Suspicious outbound beaconing on non-standard ports. |
| **`DigitalCertificate`**| **10** | Unsigned binary penalty (alone is never high risk). |

The Category Score is:
\[
S(K) = \min\left(M_K, \sum_{G \in K} S(G)\right)
\]

---

### Step 3: Context Trust Modifier
A contextual multiplier \(\Phi \in [0.0, 1.0]\) is applied based on digital provenance:
* **Valid Microsoft WHQL Signature in Safe System Path:** \(\Phi = 0.00\) (Clean system binary).
* **Valid Commercial Authenticode Certificate (e.g. Google, Valve):** \(\Phi = 0.70\) (Reduces heuristic false positives by 30%).
* **Unsigned / Self-Signed Binary:** \(\Phi = 1.00\) (Full heuristic evaluation).

---

### Step 4: Final Calculated Score
\[
S_{final} = \text{Clamp}\left( \left\lfloor \left( \sum_{K \in \mathcal{C}} S(K) \right) \times \Phi \right\rfloor, 0, 100 \right)
\]

---

## 3. Calibrated Verdict & Policy Matrix

| Final Risk Score | Verdict | Default Policy | Action / UX Response |
| :---: | :---: | :---: | :--- |
| **85 – 100** | **`ConfirmedMalicious`** | `BlockAndQuarantine` | Immediate block + DPAPI quarantine vault + Critical Alert. |
| **70 – 84** | **`HighRisk`** | `BlockAndQuarantine` | Automated containment / quarantine + Warning Alert. |
| **50 – 69** | **`Suspicious`** | `Warn` (Allow + Log) | File remains intact; logged to Security Center & Audit Log. |
| **30 – 49** | **`LowRisk`** | `Allow` (Silent Log) | File allowed; low-confidence heuristic recorded silently. |
| **0 – 29** | **`Clean`** | `Allow` | Unrestricted execution. |
