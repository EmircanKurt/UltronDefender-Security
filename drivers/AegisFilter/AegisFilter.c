#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define AEGIS_PORT_NAME L"\\AegisFilterPort"

typedef struct _AEGIS_SCAN_REQUEST {
    ULONG ProcessId;
    WCHAR FilePath[512];
    BOOLEAN IsWriteOperation;
} AEGIS_SCAN_REQUEST, *PAEGIS_SCAN_REQUEST;

typedef struct _AEGIS_SCAN_RESPONSE {
    BOOLEAN BlockAccess;
} AEGIS_SCAN_RESPONSE, *PAEGIS_SCAN_RESPONSE;

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;

FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    
    if (gClientPort == NULL || Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FltObjects->FileObject == NULL || FltObjects->FileObject->FileName.Buffer == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    AEGIS_SCAN_REQUEST request = { 0 };
    AEGIS_SCAN_RESPONSE response = { 0 };
    ULONG replyLength = sizeof(AEGIS_SCAN_RESPONSE);
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000LL; // 1 second timeout

    request.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    request.IsWriteOperation = (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
    
    RtlCopyMemory(request.FilePath, FltObjects->FileObject->FileName.Buffer, 
                  min(FltObjects->FileObject->FileName.Length, sizeof(request.FilePath) - sizeof(WCHAR)));

    NTSTATUS status = FltSendMessage(gFilterHandle, &gClientPort, &request, sizeof(request), 
                                     &response, &replyLength, &timeout);

    if (NT_SUCCESS(status) && response.BlockAccess) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS AegisConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID AegisDisconnectNotifyCallback(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
}
