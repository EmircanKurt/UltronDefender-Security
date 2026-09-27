# 🧪 ULTRON DEFENDER TOTAL SECURITY — SCORING CALIBRATION & REGRESSION TEST MATRIX

**Document:** `SCORING_CALIBRATION.md`  
**Classification:** Detection Engine Calibration & Mathematical Regression Matrix  
**Date:** 2026-08-20  

---

## 1. 10 Core Calibration Test Scenarios

| Test ID | Scenario Description | Expected Evidences | Expected Score | Expected Verdict | Action / Policy |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **TEST 01** | **Signed Normal Application (e.g. Chrome / Notepad++)** | `Signature.Valid` (-30), `KnownPublisher` | **0 – 10** | **`Clean`** | `Allow` |
| **TEST 02** | **Unsigned Normal Executable (Clean utility)** | `Signature.Unsigned` (+10) | **10** | **`Clean / LowRisk`** | `Allow` |
| **TEST 03** | **High Entropy Benign Installer (Inno Setup / 7-Zip)** | `Unsigned` (+10), `Entropy.Packer` (+35), `TLS` (+20) | **65** | **`Suspicious`** | `Warn` (Allow + Log) |
| **TEST 04** | **Single Suspicious Win32 API (`GetAsyncKeyState`)** | `Api.GetAsyncKeyState` (+15) | **15** | **`Clean / LowRisk`** | `Allow` |
| **TEST 05** | **Multi-Signal Correlated Keylogger APIs** | `SetWindowsHookEx` (+25), `WH_KEYBOARD_LL` (+20), `GetAsyncKeyState` (+15) | **45** | **`Suspicious`** | `Warn` (Allow + Log) |
| **TEST 06** | **EICAR Standard Antivirus Test File** | `Signature.EICAR` (+100) | **100** | **`ConfirmedMalicious`** | `BlockAndQuarantine` |
| **TEST 07** | **Known Ransomware Hash (WannaCry / LockBit)** | `ThreatHash.Match` (+100) | **100** | **`ConfirmedMalicious`** | `BlockAndQuarantine` |
| **TEST 08** | **Keylogger in Temp + Unsigned + AutoRun Key** | `ApiGroup` (+45), `Unsigned` (+10), `TempPath` (+25), `Persistence` (+30) | **85** | **`ConfirmedMalicious`** | `BlockAndQuarantine` |
| **TEST 09** | **Microsoft Signed System File in System32** | `ValidMicrosoft` (x0.00 Context Multiplier) | **0** | **`Clean`** | `Allow` |
| **TEST 10** | **Malware Impersonating Ultron Name** | `Unsigned` (+10), `Mimikatz.String` (+100), `ProcessInjection` (+25) | **100** | **`ConfirmedMalicious`** | `BlockAndQuarantine` |

---

## 2. Mathematical Monotonicity Proof

### Axiom of Monotonicity:
For any sample \(X\) with evidence set \(E_1\), adding an independent suspicious evidence \(e_{new} \notin E_1\) where \(s_{new} > 0\) must satisfy:
\[
S_{final}(E_1 \cup \{e_{new}\}) \ge S_{final}(E_1)
\]

### Axiom of Non-Neutralization for Definitive Threat:
For any sample containing an exact definitive malicious signature \(e_{sig} \in \text{StaticSignature}\) with \(s_{sig} \ge 90\):
\[
\text{Verdict}(E) = \mathbf{ConfirmedMalicious} \quad \forall \text{ context modifiers } \Phi
\]
Benign contextual modifiers never downgrade a confirmed malicious signature to `Clean`.
