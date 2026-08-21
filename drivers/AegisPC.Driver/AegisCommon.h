#pragma once

// Port name for filter communication
#define AEGIS_PORT_NAME L"\\AegisDriverPort"

// Max path length
#define AEGIS_MAX_PATH 520

// IOCTL codes
#define IOCTL_AEGIS_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AEGIS_SET_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Event types sent from kernel to user-mode
typedef enum _AEGIS_EVENT_TYPE {
    AegisEventProcessCreate = 1,
    AegisEventProcessTerminate = 2,
    AegisEventImageLoad = 3,
    AegisEventFileCreate = 4,
    AegisEventFileWrite = 5,
    AegisEventHandleOperation = 6
} AEGIS_EVENT_TYPE;

// Scan result sent from user-mode to kernel
typedef enum _AEGIS_SCAN_RESULT {
    AegisScanResultAllow = 0,
    AegisScanResultBlock = 1,
    AegisScanResultQuarantine = 2
} AEGIS_SCAN_RESULT;

// Event message from kernel to user-mode
typedef struct _AEGIS_EVENT_MESSAGE {
    AEGIS_EVENT_TYPE EventType;
    ULONG ProcessId;
    ULONG ParentProcessId;
    WCHAR FilePath[AEGIS_MAX_PATH];
    WCHAR ProcessName[AEGIS_MAX_PATH];
    LARGE_INTEGER Timestamp;
    ULONG64 FileSize;
    BOOLEAN IsExecutable;
} AEGIS_EVENT_MESSAGE, *PAEGIS_EVENT_MESSAGE;

// Reply from user-mode to kernel
typedef struct _AEGIS_SCAN_REPLY {
    AEGIS_SCAN_RESULT Result;
    BOOLEAN ShouldLog;
} AEGIS_SCAN_REPLY, *PAEGIS_SCAN_REPLY;
