#include <ntddk.h>
#include <fltKernel.h>
#include "AegisCommon.h"

extern NTSTATUS AegisSendEventToUser(PAEGIS_EVENT_MESSAGE Event, PAEGIS_SCAN_REPLY Reply);

VOID AegisProcessNotifyRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    AEGIS_EVENT_MESSAGE msg;
    AEGIS_SCAN_REPLY reply;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Process);

    if (ProcessId == PsGetCurrentProcessId()) {
        return; // Skip own service process
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.ProcessId = HandleToULong(ProcessId);
    KeQuerySystemTime(&msg.Timestamp);

    if (CreateInfo == NULL) {
        msg.EventType = AegisEventProcessTerminate;
        AegisSendEventToUser(&msg, NULL);
    } else {
        msg.EventType = AegisEventProcessCreate;
        msg.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        
        if (CreateInfo->ImageFileName) {
            ULONG copyLen = min(CreateInfo->ImageFileName->Length, (AEGIS_MAX_PATH - 1) * sizeof(WCHAR));
            RtlCopyMemory(msg.FilePath, CreateInfo->ImageFileName->Buffer, copyLen);
            msg.FilePath[copyLen / sizeof(WCHAR)] = L'\0';
        }

        status = AegisSendEventToUser(&msg, &reply);
        if (NT_SUCCESS(status) && reply.Result == AegisScanResultBlock) {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    }
}

VOID AegisImageLoadNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    AEGIS_EVENT_MESSAGE msg;
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName == NULL) {
        return;
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventType = AegisEventImageLoad;
    msg.ProcessId = HandleToULong(ProcessId);
    KeQuerySystemTime(&msg.Timestamp);

    ULONG copyLen = min(FullImageName->Length, (AEGIS_MAX_PATH - 1) * sizeof(WCHAR));
    RtlCopyMemory(msg.FilePath, FullImageName->Buffer, copyLen);
    msg.FilePath[copyLen / sizeof(WCHAR)] = L'\0';

    AegisSendEventToUser(&msg, NULL);
}
