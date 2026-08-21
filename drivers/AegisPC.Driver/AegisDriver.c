#include <ntddk.h>
#include <fltKernel.h>
#include "AegisCommon.h"

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
PDRIVER_OBJECT gDriverObject = NULL;

extern const FLT_REGISTRATION FilterRegistration;
extern NTSTATUS AegisUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
extern NTSTATUS AegisConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID *ConnectionPortCookie);
extern VOID AegisDisconnect(PVOID ConnectionCookie);
extern VOID AegisProcessNotifyRoutine(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
extern VOID AegisImageLoadNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
extern NTSTATUS RegisterObjectCallbacks();
extern VOID UnregisterObjectCallbacks();

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AegisUnload)

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;

    UNREFERENCED_PARAMETER(RegistryPath);
    gDriverObject = DriverObject;

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) return status;

    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    status = PsSetLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    status = RegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&uniString, AEGIS_PORT_NAME);
        InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
        status = FltCreateCommunicationPort(gFilterHandle, &gServerPort, &oa, NULL, AegisConnect, AegisDisconnect, NULL, 1);
        FltFreeSecurityDescriptor(sd);
    }

    if (!NT_SUCCESS(status)) {
        UnregisterObjectCallbacks();
        PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        UnregisterObjectCallbacks();
        PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS AegisUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    if (gServerPort) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    UnregisterObjectCallbacks();
    PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
    PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    return STATUS_SUCCESS;
}
