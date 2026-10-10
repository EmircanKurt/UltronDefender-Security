#include <ntddk.h>

extern PDRIVER_OBJECT gDriverObject;
PVOID gObRegistrationHandle = NULL;

OB_PREOP_CALLBACK_STATUS AegisPreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (PreInfo->ObjectType == *PsProcessType) {
        PEPROCESS TargetProcess = (PEPROCESS)PreInfo->Object;
        // Pseudo check: PsGetProcessImageFileName(TargetProcess) could be used
        // For demonstration, strip access if desired
        if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE || PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            // Strip access example
            // PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_TERMINATE);
        }
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterObjectCallbacks()
{
    // No arbitrary or unauthenticated legacy PID may acquire protection authority.
    return STATUS_NOT_SUPPORTED;
}

VOID UnregisterObjectCallbacks()
{
    if (gObRegistrationHandle) {
        ObUnRegisterCallbacks(gObRegistrationHandle);
        gObRegistrationHandle = NULL;
    }
}
