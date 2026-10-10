#include <ntddk.h>
#include <fltKernel.h>
#include "AegisCommon.h"

extern NTSTATUS AegisSendEventToUser(PAEGIS_EVENT_MESSAGE Event, PAEGIS_SCAN_REPLY Reply);
extern NTSTATUS AegisUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS AegisPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo;
    NTSTATUS status;
    AEGIS_EVENT_MESSAGE msg;
    AEGIS_SCAN_REPLY reply = { 0 };

    UNREFERENCED_PARAMETER(CompletionContext);
    PAGED_CODE();

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    // Simple check for executable extension logic (normally more robust)
    if (nameInfo->Extension.Length > 0) {
        // e.g. check .exe, .dll
        RtlZeroMemory(&msg, sizeof(msg));
        msg.EventType = AegisEventFileCreate;
        msg.ProcessId = HandleToULong(PsGetCurrentProcessId());
        KeQuerySystemTime(&msg.Timestamp);
        
        ULONG copyLen = min(nameInfo->Name.Length, (AEGIS_MAX_PATH - 1) * sizeof(WCHAR));
        RtlCopyMemory(msg.FilePath, nameInfo->Name.Buffer, copyLen);
        msg.FilePath[copyLen / sizeof(WCHAR)] = L'\0';

        status = AegisSendEventToUser(&msg, &reply);
        // Legacy path-only results are audit observations, never native action permits.
        UNREFERENCED_PARAMETER(status);
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS AegisPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    // Incoming bytes and stream identity are absent; do not scan old content as a write verdict.
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, AegisPreCreate, NULL },
    { IRP_MJ_WRITE, 0, AegisPreWrite, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    AegisUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
