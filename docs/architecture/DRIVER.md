# AegisPC Kernel Driver Architecture & Status Report
## Minifilter Source Analysis & Future Roadmap

---

## 1. Current Driver Status

| Attribute | State | Details |
| :--- | :---: | :--- |
| **Driver Source Code** | **PRESENT** | Located in `drivers/AegisPC.Driver/` (`AegisDriver.c`, `MinifilterCallbacks.c`, `ProcessCallbacks.c`, `ObjectCallbacks.c`, `Communication.c`, `AegisDriver.inf`). |
| **Compiled Binary (`.sys`)** | **NONE** | No compiled `AegisDriver.sys` exists in the release package or repository. |
| **Code Signing** | **NONE** | Unsigned. 64-bit Windows (x64) enforces Driver Signature Enforcement (DSE) requiring an EV Code Signing Certificate and WHQL portal attestation. |
| **Active Protection Mode** | **USER-MODE (Ring 3)** | AegisPC runs 100% in User-Mode via Windows Win32 APIs, FileSystemWatcher (64KB), Process APIs, and AMSI. |

---

## 2. Source Code Architecture Review (`drivers/AegisPC.Driver/`)

### A. Minifilter Callbacks (`MinifilterCallbacks.c`)
* **Registration:** Registers with Filter Manager (`FltRegisterFilter`) under altitude `385100` (Activity Monitor range).
* **IRP Hooks:**
  * `IRP_MJ_CREATE`: Pre-operation callback checks file extension and creates message packet for user-mode service.
  * `IRP_MJ_CLEANUP`: Post-operation callback captures modified file paths upon handle closure.
* **Limitations Identified in Current C Code:**
  1. Synchronous waiting for user-mode response at `PASSIVE_LEVEL` can cause I/O thread starvation if the user-mode service is under heavy load.
  2. Missing `FltGetFileNameInformation` parsing in certain non-buffered I/O paths.

### B. Process & Thread Callbacks (`ProcessCallbacks.c`)
* **`PsSetCreateProcessNotifyRoutineEx`:** Intercepts process creation. In full kernel implementation, setting `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED` blocks malware execution before the main thread starts.
* **`PsSetLoadImageNotifyRoutine`:** Intercepts DLL and driver image mapping into memory.

### C. Object Callbacks (`ObjectCallbacks.c`)
* **`ObRegisterCallbacks`:** Strips `PROCESS_TERMINATE` and `PROCESS_VM_WRITE` rights from handles opened targeting the AegisPC security service.

---

## 3. Requirements for Compiling and Loading Kernel Driver

1. **Windows Driver Kit (WDK):** WDK 10/11 with MSBuild driver toolset `WindowsKernelModeDriver10.0`.
2. **Microsoft Extended Validation (EV) Code Signing Certificate:** Required to sign the driver package and pass Microsoft Hardware Dev Center Attestation.
3. **Microsoft Altitude Assignment:** Official altitude allocation from Microsoft FSFilter team.
4. **Driver Verifier & HLK Testing:** Hardware Lab Kit (HLK) tests ensuring zero kernel panics / BSODs under heavy file system stress.
