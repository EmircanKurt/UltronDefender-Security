# 🔍 ULTRON DEFENDER TOTAL SECURITY — RISK SCORE TRACE AUDIT

**Document:** `RISK_SCORE_TRACE.md`  
**Sample Analyzed:** `UltronDefender_Setup_v3.0.exe`  
**SHA-256:** `fb984dc03880350245297aaf517fdfc61f531dd6416e26975e46caa32df3e333`  
**Date:** 2026-08-20  

---

## 1. Step-by-Step Score Trace

```text
================================================================================
ULTRON DEFENDER RISK ENGINE — AUDITABLE SCORE TRACE
================================================================================
Target File:   c:\Users\PC\Documents\gemini virüs program\UltronDefender_Setup_v3.0.exe
File Size:     103,385,703 bytes (98.60 MB)
Entropy:       7.9200 / 8.0000
Signature:     Unsigned (No Authenticode Certificate)
PE Type:       PE32 (Inno Setup Unpacker Stub)

[STAGE 1: RAW EVIDENCE COLLECTION]
 1. [DigitalCertificate] [DigitalSignature] Signature.Unsigned.Binary (+10, Conf: Low)
 2. [DigitalCertificate] [DigitalSignature] Cert.UnsignedExecutable   (+10, Conf: Medium)
 3. [EntropyAnomaly]     [Packing]          Entropy.Extreme.Packer    (+35, Conf: Medium)
 4. [StaticPeStructure]  [PeStructure]      PE_TLS_CALLBACK_DETECTED  (+20, Conf: High)
 5. [EntropyAnomaly]     [Packing]          PE_PACKED_SECTION_.RSRC   (+25, Conf: High)

--------------------------------------------------------------------------------
Raw Arithmetic Sum: 10 + 10 + 35 + 20 + 25 = 100 / 100
--------------------------------------------------------------------------------

[STAGE 2: CORRELATION GROUP DEDUPLICATION]
 • Group 'DigitalSignature' (Category: DigitalCertificate):
     - Dominant Signal:     +10 (Cert.UnsignedExecutable)
     - Corroborating Sum:   +10 (Signature.Unsigned.Binary)
     - Corroboration Bonus: Floor(10 / 4) = +2
     -> Group Score:        10 + 2 = 12

 • Group 'Packing' (Category: EntropyAnomaly):
     - Dominant Signal:     +35 (Entropy.Extreme.Packer)
     - Corroborating Sum:   +25 (PE_PACKED_SECTION_.RSRC)
     - Corroboration Bonus: Floor(25 / 4) = +6
     -> Group Score:        35 + 6 = 41

 • Group 'PeStructure' (Category: StaticPeStructure):
     - Dominant Signal:     +20 (PE_TLS_CALLBACK_DETECTED)
     - Corroborating Sum:   0
     - Corroboration Bonus: 0
     -> Group Score:        20

--------------------------------------------------------------------------------
Deduplicated Group Sum: 12 + 41 + 20 = 73
--------------------------------------------------------------------------------

[STAGE 3: CATEGORY SCORE CAPPING]
 • DigitalCertificate: GroupSum = 12 | Cap = 10  -> Effective Category Score = 10
 • EntropyAnomaly:     GroupSum = 41 | Cap = 35  -> Effective Category Score = 35
 • StaticPeStructure:  GroupSum = 20 | Cap = 40  -> Effective Category Score = 20

--------------------------------------------------------------------------------
Category Adjusted Sum: 10 + 35 + 20 = 65
--------------------------------------------------------------------------------

[STAGE 4: CONTEXT TRUST MODIFIER]
 • File is unsigned development executable outside System32 -> Context Multiplier = 1.00

--------------------------------------------------------------------------------
FINAL CALCULATED RISK SCORE: 65 / 100
FINAL VERDICT:               Suspicious (65/100)
RECOMMENDED POLICY:          Warn (Allow + Audit Log; NEVER DELETE)
--------------------------------------------------------------------------------
```

---

## 2. Mathematical Integrity Conclusion

1. **Deterministic & Explainable:**  
   The score \(65/100\) is the exact, reproducible outcome of **Group Deduplication** (100 \(\to\) 73) followed by **Category Capping** (73 \(\to\) 65).
2. **Safety & Policy Invariant Preserved:**  
   Because \(65 < 70\), the file is **ALLOWED** and **LOGGED**. It does **NOT** trigger an active quarantine, proving that legitimate unsigned compressed installers are not falsely classified as malicious.
