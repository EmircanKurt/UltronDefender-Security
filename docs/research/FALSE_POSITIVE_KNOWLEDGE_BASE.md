# 🛡️ FALSE POSITIVE KNOWLEDGE BASE — DEFENSIVE CONTEXT ENGINE
**Project:** Ultron Defender Total Security  
**Document:** `FALSE_POSITIVE_KNOWLEDGE_BASE.md`  
**Classification:** Detection Reliability & Noise Reduction  
**Date:** 2026-08-19  

---

## 1. The False Positive Problem

An antivirus or EDR that flags benign developer, administrative, or gaming software destroys user trust and leads users to disable protection. **Ultron Defender adheres to the Context-Aware Verification Principle:** An API or behavioral indicator is never evaluated in isolation; it must be qualified by publisher signature, process lineage, installation path, and user interaction.

---

## 2. Benign Software Indicator & Context Matrix

| Software Category | Legitimate Software Examples | Suspicious Signals Produced (Mimicking Malware) | Contextual Differentiation Factors (Why It Is Benign) | Ultron Allowlist & Context Rules |
| :--- | :--- | :--- | :--- | :--- |
| **Compilers, IDEs & Build Tools** | Visual Studio (`devenv.exe`), `cl.exe`, `gcc.exe`, `rustc.exe`, `dotnet.exe`, `javac.exe` | Rapid file writes of unverified `.exe`/`.dll` in Temp/Debug folders; high CPU; command-line compilation. | Process tree originates from IDE; files written inside project/repo directories; signed parent process. | Exclude verified project folders when developer profile is active; check parent PID lineage. |
| **Debuggers & Profilers** | WinDbg, Visual Studio Debugger, x64dbg, Cheat Engine, Intel VTune | Calls `OpenProcess(PROCESS_ALL_ACCESS)`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `DebugActiveProcess`. | Process explicitly attached by user; interactive GUI window; valid digital signature on debuggers. | Check if process has `SeDebugPrivilege` granted intentionally; require user prompt if unsigned debugger attaches to critical service. |
| **Game Launchers & Anti-Cheat** | Steam, Epic Games Launcher, EA App, Easy Anti-Cheat (`EasyAntiCheat.sys`), BattlEye | Kernel driver loading, process memory scanning, thread suspension, keyboard/mouse hooking, overlay injection. | Valid Authenticode/WHQL digital signatures; installed under `Program Files`; known publisher certificates. | Signature trust check (`AuthenticodeDetector`); verify signer against known publisher list (Valve, Epic, Microsoft). |
| **Gaming & Communication Overlays** | Discord Overlay, GeForce Experience (`nvspcaps64.exe`), OBS Studio, RivaTuner | Installs global Windows hooks (`SetWindowsHookEx`), injects `DirectX`/`Vulkan` rendering DLLs into game processes. | Only targets fullscreen DirectX/OpenGL child windows; valid signature; user-initiated application launch. | Overlay detection rule suppresses DLL injection alerts if target process is a registered 3D graphic application. |
| **Accessibility & Screen Readers** | Windows Narrator, NVDA, JAWS, AutoHotkey (User scripts) | Global keyboard/mouse hooks (`WH_KEYBOARD_LL`, `WH_MOUSE_LL`), `GetAsyncKeyState` polling, UI Automation traversal. | Valid digital signature; long-running service lifetime; lack of hidden log file writes or outbound raw IP traffic. | Ensure keyboard hook alone does NOT trigger quarantine; requires second-stage staging or C2 traffic. |
| **Backup & Cloud Sync Utilities** | OneDrive, Google Drive, Dropbox, Veeam, Macrium Reflect | High-frequency file reading, mass file renames/moves across User directories, shadow copy interaction. | Operates under recognized service accounts; valid publisher signature; does not increase file entropy. | Canary file verification (backup tools do NOT modify canary tokens); entropy delta check remains neutral. |
| **Remote Management & Support** | TeamViewer, AnyDesk, RustDesk, Splashtop | Inbound network listening, screen frame capture, remote keyboard/mouse simulation, service installation. | Valid digital signature; user interaction dialog; established binary reputation. | Verified digital certificate; known publisher allowlist. |
| **Software Installers & Updaters** | Inno Setup, NSIS, WiX MSI, Chrome Update, EdgeUpdate | Drops unsigned files into `%TEMP%`, writes to `HKCU\...\Run`, executes command scripts (`.bat`, `.cmd`). | Parent process is interactive installer; writes to `Program Files`; digital signature on installer bundle. | Contextual installer rule: Temporary files dropped during active installer run are scanned statically without flagging the installer as a Trojan dropper. |
| **Script Automation & Sysadmin Tools** | PowerShell ISE, Windows Terminal, Sysinternals (`procmon.exe`, `procexp.exe`) | WMI queries, Service querying, Process listing, Registry inspection. | Runs under administrative session; binary signed by Microsoft Corporation; executed interactively. | Verified Microsoft WHQL signature; trusted system path check (`PathHelper.IsKnownSafePath`). |

---

## 3. Five Golden Rules for False Positive Prevention

1. **Rule 1 — Never Alert on a Single API:** An import or API call (`SetWindowsHookEx`, `CreateRemoteThread`, `VirtualAllocEx`) is a *feature*, not a crime. Only alert when combined with staging, persistence, or network anomalies.
2. **Rule 2 — Digital Signatures as Risk Dampeners:** A valid Authenticode signature from a known commercial root authority reduces behavioral suspicion score by 15% to 60% (unless process hollowing or canary tampering is observed).
3. **Rule 3 — Preserve Known System & Program Files:** Operating system executables (`C:\Windows\System32\*`) and verified applications (`C:\Program Files\*`) are never quarantined without confirmed binary tampering or process injection.
4. **Rule 4 — Canary File Isolation:** Ransomware heuristics rely on untouched honeypot canary files. Legitimate compilers and backup tools never touch hidden `.canary` files.
5. **Rule 5 — UNKNOWN = ALLOW + LOG (Never UNKNOWN = DELETE):** If a file has an unknown hash or borderline score (Score 30–49), it is allowed to run while behavioral telemetry logs its execution for post-event correlation.
