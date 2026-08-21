# ⚡ REAL-TIME PROTECTION RESEARCH & SUBSYSTEM DESIGN
**Project:** Ultron Defender Total Security  
**Document:** `REALTIME_RESEARCH.md`  
**Classification:** Real-Time Shield Engineering  
**Date:** 2026-08-19  

---

## 1. Subsystem Architecture

The real-time protection subsystem in Ultron Defender operates on a continuous, low-latency pipeline designed to intercept file arrivals, process creation, script execution, and ransomware activity without degrading user experience.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. WATCHDOG OBSERVERS                                                       │
│    - FileSystemWatcher across Desktop, Downloads, Temp, Startup, AppData    │
│    - ProcessMonitorService tracking live process trees & LOLBin invocations  │
│    - AmsiScanService inspecting memory-resident scripts (PowerShell, VBS)   │
│    - RansomwareProtectionEngine monitoring canary traps & burst writes      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. DEBOUNCE & DISK-STABILITY ENGINE                                         │
│    - Rapid-write debounce (4-second sliding window per path)                │
│    - Browser write completion delay (500ms for .crdownload / .tmp locks)    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. CONTENT-OVER-EXTENSION SNIFFER                                           │
│    - Magic byte header check: MZ, PK, 7z, Rar!, Scripts                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. DETECTIONHUB MULTI-SIGNAL PIPELINE                                       │
│    - 13 Modular Detector Plugins evaluate file context                      │
│    - Category risk capping & evidence aggregation                           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 5. RESPONSE & NOTIFICATION AGGREGATOR                                       │
│    - Risk >= 85: Immediate Containment (Process Kill + DPAPI Vault)         │
│    - Routine threats: 3–5s Batch Grouping via NotificationAggregator        │
│    - Clean files: Silent allow (Zero notification noise)                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Real-Time Performance & Debouncing Strategy

* **Problem:** Browsers (Chrome, Edge, Firefox) write files in multiple chunks (e.g. creating `file.crdownload`, writing blocks, and renaming to `file.exe`). Naive watchers attempt to scan the locked temporary chunk immediately, throwing `IOException` or scanning incomplete data.
* **Ultron Solution:**
  1. **Event Filtering:** Listen to both `Created`, `Changed`, and `Renamed` events.
  2. **Debounce Cache:** Keep a thread-safe `ConcurrentDictionary<string, DateTime> _recentlyScanned` with a 4-second debounce threshold.
  3. **Non-Blocking Write Delay:** Insert a lightweight 500ms asynchronous non-blocking delay (`await Task.Delay(500)`) before file inspection to allow the browser or installer to release its write handle.
  4. **Watchdog on Ignored Items:** If a file previously marked as "Ignored" attempts to create or execute new binaries, the watchdog triggers an instant lockdown and overrides the ignore flag.
