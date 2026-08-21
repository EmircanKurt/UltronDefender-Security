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
    OB_CALLBACK_REGISTRATION callbackReg;
    OB_OPERATION_REGISTRATION opReg;

    RtlZeroMemory(&opReg, sizeof(opReg));
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = AegisPreOperationCallback;
    opReg.PostOperation = NULL;

    RtlZeroMemory(&callbackReg, sizeof(callbackReg));
    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&callbackReg.Altitude, L"385100");
    callbackReg.RegistrationContext = NULL;
    callbackReg.OperationRegistration = &opReg;

    return ObRegisterCallbacks(&callbackReg, &gObRegistrationHandle);
}

VOID UnregisterObjectCallbacks()
{
    if (gObRegistrationHandle) {
        ObUnRegisterCallbacks(gObRegistrationHandle);
        gObRegistrationHandle = NULL;
    }
}
