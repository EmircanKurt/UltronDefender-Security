# ULTRON DEFENDER TOTAL SECURITY — KERNEL DRIVER ROADMAP & IMPLEMENTATION PLAN

## 1. Executive Summary & Honest Baseline

As established during the master audit and verification phase, Ultron Defender Total Security currently operates in **User-Mode Only** mode:
- `KernelMinifilterEngine.Status` honestly reports `KernelDriverStatus.NotInstalled`.
- Kernel-level interception files exist in source code (`drivers/AegisFilter/` and `drivers/AegisPC.Driver/`), but require native Windows Driver Kit (WDK) compilation, test-signing, or Microsoft WHQL/EV code signing before Windows 10/11 x64 OS will load them into kernel space (`ntoskrnl.exe`).
- This document outlines the authoritative engineering roadmap to transition Ultron Defender from a user-mode scanner with ETW/FileSystemWatcher telemetry to a full ring-0 kernel minifilter with inline pre-execution blocking.

---

## 2. Existing Architecture & Source Code Inventory

The repository contains two driver modules:
1. **`drivers/AegisPC.Driver/` (Modern Minifilter & Object Callbacks)**:
   - `AegisDriver.c`: DriverEntry, DriverUnload, FLT_REGISTRATION, FilterCommunicationPort initialization.
   - `MinifilterCallbacks.c`: `PreCreate`, `PostCreate`, `PreWrite` filesystem interception hooks.
   - `ProcessCallbacks.c`: `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`.
   - `ObjectCallbacks.c`: `ObRegisterCallbacks` to strip `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` handles opened against protected AV processes (Self-Defense).
   - `Communication.c`: `FltCreateCommunicationPort`, `FltSendMessage`, client connect/disconnect handlers.
   - `AegisCommon.h`: Shared C contracts matching C# P/Invoke structs (`AegisEventProcessCreate`, `AEGIS_SCAN_REPLY`, etc.).
2. **`drivers/AegisFilter/` (Alternative Minifilter)**:
   - `AegisFilter.c`, `SelfDefense.c`, `AegisFilter.inf`.

---

## 3. Implementation Phases

### Phase 1: Toolchain & Build Environment Setup
1. **Prerequisites**:
   - Visual Studio 2022 (v143 toolset) with C++ Desktop Development.
   - Windows 11 SDK (version 10.0.22621.0 or newer).
   - Windows Driver Kit (WDK) matching the installed SDK.
2. **Project File Creation**:
   - Create `drivers/AegisPC.Driver/AegisDriver.vcxproj` using `DriverType=KMDF` (or native Minifilter with `fltKernel.lib`, `ntoskrnl.lib`).
   - Configure target platform `x64` with Release/Debug configurations.
   - Enable Spectre mitigation (`/Qspectre`), Control Flow Guard (`/guard:cf`), and SAL annotations.

### Phase 2: Test-Signing & Local Development Deployment
Windows 64-bit strictly enforces Kernel Mode Code Signing (KMCS). For development and internal QA:
1. **Enable Test-Signing**:
   ```cmd
   bcdedit /set testsigning on
   ```
2. **Create Test Certificate & Sign**:
   ```cmd
   makecert -r -pe -ss PrivateCertStore -n "CN=UltronDefenderDevelopment" UltronDefenderTest.cer
   certmgr.exe /add UltronDefenderTest.cer /s /r localMachine root
   signtool sign /v /s PrivateCertStore /n "UltronDefenderDevelopment" /t http://timestamp.digicert.com AegisDriver.sys
   ```
3. **Install INF & Register Service**:
   ```cmd
   rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 .\AegisDriver.inf
   sc create AegisDriver type= kernel binPath= "C:\Windows\System32\drivers\AegisDriver.sys"
   fltmc load AegisDriver
   ```

### Phase 3: Minifilter Altitude Registration
Minifilters are loaded by the Filter Manager (`fltmgr.sys`) in strict order according to their assigned **Altitude**.
- Required Filter Category: **Anti-Virus** (Altitude Range: `320000 - 329999`).
- Example Assigned Altitude: `320700` (requires Microsoft approval/reservation for production release).
- INF Configuration:
  ```inf
  [AegisDriver.Service]
  DisplayName    = "Ultron Defender Minifilter Driver"
  Description    = "Ultron Defender Real-Time Security Minifilter"
  ServiceType    = 2 ; SERVICE_FILE_SYSTEM_DRIVER
  StartType      = 2 ; SERVICE_AUTO_START
  ErrorControl   = 1 ; SERVICE_ERROR_NORMAL
  LoadOrderGroup = "FSFilter Anti-Virus"
  AddReg         = AegisDriver.AddRegistry
  ```

### Phase 4: User-Mode to Kernel-Mode IPC (C# Integration)
1. **Filter Communication Port**:
   - Kernel registers port: `FltCreateCommunicationPort(..., L"\\AegisDriverPort", ...)`.
   - C# `KernelMinifilterEngine.cs` connects using `FilterConnectCommunicationPort`:
     ```csharp
     [DllImport("fltlib.dll", SetLastError = true)]
     public static extern int FilterConnectCommunicationPort(
         [MarshalAs(UnmanagedType.LPWStr)] string portName,
         uint options,
         IntPtr context,
         ushort sizeOfContext,
         IntPtr securityAttributes,
         out SafeFileHandle portHandle);
     ```
2. **Pre-Execution Synchronous Scanning Loop**:
   - On `PreCreate` of an executable, kernel sends message to user-mode via `FltSendMessage`.
   - Kernel thread waits synchronously (or with a 3-second safety timeout).
   - User-mode `KernelMinifilterEngine` receives `_AEGIS_EVENT_MESSAGE`, computes hash, checks allowlist/signatures, and replies with `_AEGIS_SCAN_REPLY`:
     - If `AegisScanResultBlock`, kernel returns `STATUS_ACCESS_DENIED`. The file never executes or opens.
     - If `AegisScanResultAllow`, kernel returns `FLT_PREOP_SUCCESS_NO_CALLBACK`.
3. **Self-Defense Verification**:
   - `ObRegisterCallbacks` intercepts `OB_OPERATION_HANDLE_CREATE` and `OB_OPERATION_HANDLE_DUPLICATE`.
   - If target process is `UltronDefender.exe` or `AegisPC.Service.exe`, strips `PROCESS_TERMINATE`, `PROCESS_SUSPEND_RESUME`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`.
   - Prevents malware (even running as Administrator) from terminating or injecting into the AV engine.

### Phase 5: Production Code Signing & WHQL
For production deployment on customer machines without `bcdedit /set testsigning on`:
1. **EV Code Signing Certificate**: Hardware Token (YubiKey / Cloud HSM) with Extended Validation.
2. **Microsoft Hardware Developer Center (WHDC)** registration.
3. **HLK (Hardware Lab Kit) Tests**: Pass Filter Verification Tests (`fltverifier.sys`) and Driver Verifier.
4. **Attestation Signing / WHQL**: Submit `.hlkx` package to Microsoft for WHQL signature.

---

## 4. Summary Matrix: User-Mode Fallback vs Kernel Minifilter

| Feature | Current Implementation (User-Mode) | Future Implementation (Kernel Driver) |
| :--- | :--- | :--- |
| **Driver Status** | `KernelDriverStatus.NotInstalled` (100% Honest) | `KernelDriverStatus.Running` |
| **File Interception** | Post-creation (`FileSystemWatcher` + ETW) | Pre-execution (`IRP_MJ_CREATE` / `PreCreate`) |
| **Bypass Resistance** | High (Hardened DACL, SDDL `WD` deny) | Maximum (Kernel `ObRegisterCallbacks`, strips handle rights) |
| **Zero-Day Dropper Protection** | Millisecond delay before quarantine | 0ms lock before file read/write completes |
| **Process Termination Protection** | Process ACL restricted via Win32 API | Kernel-level protection against `OpenProcess` |
