#include <ntddk.h>
#include <fltKernel.h>
#include "AegisCommon.h"

extern PFLT_PORT gClientPort;
extern PFLT_FILTER gFilterHandle;

NTSTATUS AegisConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID AegisDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (gClientPort) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
}

NTSTATUS AegisSendEventToUser(PAEGIS_EVENT_MESSAGE Event, PAEGIS_SCAN_REPLY Reply)
{
    ULONG replyLength = 0;
    if (Reply) RtlZeroMemory(Reply, sizeof(*Reply));
    LARGE_INTEGER timeout;
    NTSTATUS status;

    if (!gClientPort) {
        if (Reply) Reply->Result = AegisScanResultAllow;
        return STATUS_PORT_DISCONNECTED;
    }

    if (Reply) {
        replyLength = sizeof(AEGIS_SCAN_REPLY);
    }

    timeout.QuadPart = -2000000; // Bounded 200 ms audit exchange; never an enforcement deadline.

    status = FltSendMessage(gFilterHandle, &gClientPort, Event, sizeof(AEGIS_EVENT_MESSAGE), Reply, &replyLength, &timeout);

    if (status != STATUS_SUCCESS || (Reply && replyLength != sizeof(AEGIS_SCAN_REPLY))) {
        if (Reply) Reply->Result = AegisScanResultAllow;
    }

    return status;
}
