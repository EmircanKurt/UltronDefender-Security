#include <ntddk.h>

PVOID gRegistrationHandle = NULL;
ULONG gProtectedPid = 0;

OB_PREOP_CALLBACK_STATUS AegisPreOpenProcess(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    ULONG targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProcess);

    if (targetPid == gProtectedPid && gProtectedPid != 0) {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
            OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
        }
    }

    return OB_PREOP_SUCCESS;
}
