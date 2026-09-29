# 🔒 SECURITY POLICY & VULNERABILITY DISCLOSURE

Ultron Defender Total Security is committed to security and transparency. We welcome responsible security vulnerability reports from the security research community.

---

## 1. Supported Versions

| Version | Supported | Security Updates |
| :--- | :---: | :--- |
| **v3.2.1 development branch** | Best effort | Experimental preview; no production security-support guarantee |
| **v3.0.x / v2.x / v1.x** | No | Older code; upgrade and revalidate before use |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability, privilege escalation, bypass, or denial-of-service issue in Ultron Defender:

1. **Do NOT open a public GitHub issue.**
2. Please submit your finding privately via **GitHub Private Vulnerability Reporting** (under the `Security` tab of this repository) or email the maintainers directly.
3. Include:
   * A clear technical description of the vulnerability.
   * Steps to reproduce, proof-of-concept (PoC) code, or execution trace.
   * Impact assessment (e.g. Local Privilege Escalation, Evasion, Denial of Service).
   * Affected operating system version and build.

---

## 3. Vulnerability Handling

Reports are handled on a best-effort basis. This experimental project does not promise a fixed acknowledgment, triage, patch, or advisory timeline. Do not rely on it as the sole protection for a production device.

---

## 4. Scope & Guidelines

* **In Scope:**
  * Local privilege escalation via ElevatedHelper or Windows Service.
  * DPAPI Quarantine vault decryption bypass or plaintext leaks.
  * Memory corruption, arbitrary code execution, or denial of service in `FileScannerService` / `SecureArchiveEngine`.
  * Single-instance mutex manipulation allowing concurrent process corruption.
* **Out of Scope:**
  * Attacks requiring physical access to an unlocked administrator desktop with root debugger attached.
  * Malware executing with `NT AUTHORITY\SYSTEM` or kernel driver privileges prior to Ultron Defender installation.
