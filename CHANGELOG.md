# 📜 CHANGELOG — ULTRON DEFENDER TOTAL SECURITY

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-08-19

### Added
* **Content-Over-Extension Magic Sniffer:** Inspects binary headers (`MZ`, `PK`, `7z`, `Rar!`, `#!`) to detect disguised PE payloads regardless of extension (`.dat`, `.bin`, `.tmp`).
* **Priority Drop Zone Indexing:** Full and Quick scans prioritize user Desktop, Downloads, Temp, and Startup in the first 1–2 seconds.
* **NotificationAggregator:** 3–5 second grouping window that aggregates up to 20 simultaneous routine threats into a single clean summary notification.
* **Single-Instance Mutex & Focus Manager:** Added `Global\UltronDefender_SingleInstance_Mutex` and Inno Setup `InitializeSetup` registry check.
* **Modular DetectionHub Integration:** Connected all 13 detector plugins to Full, Quick, Custom, and Startup scans.
* **Live Host Performance Benchmark:** Measured scan throughput (P50 = 3.82ms, P95 = 28.40ms, P99 = 41.15ms).

### Fixed
* **Full Scan Desktop False Negative:** Fixed root cause where `Directory.EnumerateFiles("C:\\")` aborted on junction points (`System Volume Information`, `$Recycle.Bin`). Replaced with resilient `EnumerateDirectorySafelyAsync` BFS queue.
* **Extension Filter Blind Spot:** Removed hardcoded 16-extension filter that was skipping `.bin`, `.dat`, `.tmp`, `.vbe`, `.hta`, and extensionless binaries.
* **Locked File Crash:** Applied `FileShare.ReadWrite | FileShare.Delete` with retry logic for files actively locked by browsers.
* **Duplicate Re-install Collision:** Inno setup now halts duplicate installation and prompts the user cleanly.

### Security
* Verified 20-threat DPAPI AES-256 atomic quarantine vault isolation.
* Enhanced AMSI script in-memory buffer inspection.
* Zero-mock automated test suite expanded to 202 tests (100% passing).

---

## [2.0.0] - 2026-08-18

### Added
* Deep PE Analyzer with Rich Header XOR decoding, TLS callback detection, and W+X section anomaly checks.
* Multi-layer scan caching (L1 RAM LRU + L2 SQLite Disk DB).
* Process Lineage Tracker and 60-second sliding window Attack Chain Correlator.
* Ransomware mass file burst and Shannon entropy delta guard.
* Safe Archive Engine with zip bomb quotas and recursion depth limits.
