#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Minifilter callbacks do not require encoded function pointers")

// ============================================================================
// SABİTLER VE BELLEK HAVUZU TANIMLARI
// ============================================================================

#define AEGIS_FILTER_TAG          'sgeA'          // Bellek etiketimiz: 'Aegs'
#define AEGIS_PORT_NAME           L"\\AegisFilterPort"
#define AEGIS_MAX_PATH_CHARS      512

// Kontrol mesajı kodları (User-Mode -> Kernel-Mode)
#define AEGIS_MSG_REGISTER_PROTECTED_PID 0x1001
#define AEGIS_MSG_QUERY_STATUS           0x1002

// ExAllocatePool2 (Modern WDK / Windows 10 2004+ / Windows 11) geriye dönük uyumluluk makrosu
#if !defined(ExAllocatePool2)
    #define AegisAllocatePaged(size)    ExAllocatePoolWithTag(PagedPool, (size), AEGIS_FILTER_TAG)
    #define AegisAllocateNonPaged(size) ExAllocatePoolWithTag(NonPagedPoolNx, (size), AEGIS_FILTER_TAG)
#else
    #define AegisAllocatePaged(size)    ExAllocatePool2(POOL_FLAG_PAGED, (size), AEGIS_FILTER_TAG)
    #define AegisAllocateNonPaged(size) ExAllocatePool2(POOL_FLAG_NON_PAGED, (size), AEGIS_FILTER_TAG)
#endif

// ============================================================================
// VERİ YAPILARI (RING-0 / RING-3 PROTOKOLÜ)
// ============================================================================

// Ring-3 (KernelIpcService.cs) tarafındaki struct ScanRequest ile bayt bayt birebir eşleşir
typedef struct _AEGIS_SCAN_REQUEST {
    ULONG   ProcessId;
    WCHAR   FilePath[AEGIS_MAX_PATH_CHARS];
    BOOLEAN IsWriteOperation;
} AEGIS_SCAN_REQUEST, *PAEGIS_SCAN_REQUEST;

// Ring-3 (KernelIpcService.cs) tarafındaki struct ScanResponse ile birebir eşleşir
typedef struct _AEGIS_SCAN_RESPONSE {
    BOOLEAN BlockAccess;
} AEGIS_SCAN_RESPONSE, *PAEGIS_SCAN_RESPONSE;

// User-Mode tarafından gönderilen kontrol komutu yapısı
typedef struct _AEGIS_CONTROL_COMMAND {
    ULONG CommandCode;
    ULONG ProcessId;
} AEGIS_CONTROL_COMMAND, *PAEGIS_CONTROL_COMMAND;

// Pre-Create aşamasından Post-Create aşamasına güvenle aktarılan bağlam verisi
typedef struct _AEGIS_PRE_2_POST_CONTEXT {
    BOOLEAN IsCreationAttempt;
    BOOLEAN IsWriteOperation;
    ULONG   ProcessId;
    WCHAR   FilePath[AEGIS_MAX_PATH_CHARS];
} AEGIS_PRE_2_POST_CONTEXT, *PAEGIS_PRE_2_POST_CONTEXT;

// ============================================================================
// GLOBAL SÜRÜCÜ DEĞİŞKENLERİ
// ============================================================================

PFLT_FILTER gFilterHandle          = NULL;
PFLT_PORT   gServerPort            = NULL;
PFLT_PORT   gClientPort            = NULL;
PDRIVER_OBJECT gDriverObject       = NULL;
PVOID       gObRegistrationHandle  = NULL;
ULONG       gProtectedPid          = 0;

// ============================================================================
// FONKSİYON BİLDİRİMLERİ (FORWARD DECLARATIONS)
// ============================================================================

DRIVER_INITIALIZE DriverEntry;

NTSTATUS AegisFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS AegisInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

NTSTATUS AegisInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID AegisInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID AegisInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS AegisPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

VOID AegisProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID AegisImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);

OB_PREOP_CALLBACK_STATUS AegisPreOpenProcess(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);

NTSTATUS RegisterObjectCallbacks(VOID);
VOID UnregisterObjectCallbacks(VOID);

NTSTATUS AegisConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie);

VOID AegisDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie);

NTSTATUS AegisMessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength);

// Sayfalanabilir bellek (Paged Code) atamaları
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AegisFilterUnload)
#pragma alloc_text(PAGE, AegisInstanceSetup)
#pragma alloc_text(PAGE, AegisInstanceQueryTeardown)
#pragma alloc_text(PAGE, AegisInstanceTeardownStart)
#pragma alloc_text(PAGE, AegisInstanceTeardownComplete)
#pragma alloc_text(PAGE, AegisPreCreate)
#pragma alloc_text(PAGE, AegisPreWrite)
#pragma alloc_text(PAGE, AegisConnectNotifyCallback)
#pragma alloc_text(PAGE, AegisDisconnectNotifyCallback)
#pragma alloc_text(PAGE, AegisMessageNotifyCallback)

// ============================================================================
// MINIFILTER OPERASYON VE KAYIT TABLOLARI (FLT_REGISTRATION)
// ============================================================================

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        AegisPreCreate,
        AegisPostCreate
    },
    {
        IRP_MJ_WRITE,
        0,
        AegisPreWrite,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    NULL,                               // ContextRegistration
    Callbacks,                          // OperationRegistration
    AegisFilterUnload,                  // FilterUnloadCallback
    AegisInstanceSetup,                 // InstanceSetupCallback
    AegisInstanceQueryTeardown,         // InstanceQueryTeardownCallback
    AegisInstanceTeardownStart,         // InstanceTeardownStartCallback
    AegisInstanceTeardownComplete,      // InstanceTeardownCompleteCallback
    NULL,                               // GenerateFileNameCallback
    NULL,                               // NormalizeNameComponentCallback
    NULL                                // NormalizeContextCleanupCallback
};

// ============================================================================
// SÜRÜCÜ GİRİŞ NOKTASI (DRIVER ENTRY)
// ============================================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);
    PAGED_CODE();

    gDriverObject = DriverObject;
    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] DriverEntry baslatiliyor...\n"));

    // 1. Minifilter sürücüsünü Filtre Yöneticisine (Filter Manager) kaydet
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltRegisterFilter hatasi: 0x%08X\n", status));
        return status;
    }

    // 2. Pre-Execution Süreç Oluşturma Callback'ini kaydet (PsSetCreateProcessNotifyRoutineEx)
    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "[AegisFilter] PsSetCreateProcessNotifyRoutineEx basarisiz: 0x%08X (Devam ediliyor)\n", status));
    }

    // 3. İmaj / DLL Yükleme Bildirim Callback'ini kaydet (PsSetLoadImageNotifyRoutine)
    status = PsSetLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "[AegisFilter] PsSetLoadImageNotifyRoutine basarisiz: 0x%08X (Devam ediliyor)\n", status));
    }

    // 4. Ring-0 Self-Defense Callback'ini kaydet (ObRegisterCallbacks)
    status = RegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "[AegisFilter] RegisterObjectCallbacks basarisiz: 0x%08X (Devam ediliyor)\n", status));
    }

    // 5. İletişim portu için varsayılan güvenlik tanımlayıcısını oluştur
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltBuildDefaultSecurityDescriptor hatasi: 0x%08X\n", status));
        UnregisterObjectCallbacks();
        PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // 6. İletişim Portu nesne niteliklerini ilklendir
    RtlInitUnicodeString(&portName, AEGIS_PORT_NAME);
    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        sd);

    // 7. Çift yönlü filtre iletişim portunu oluştur (\AegisFilterPort)
    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &oa,
        NULL,
        AegisConnectNotifyCallback,
        AegisDisconnectNotifyCallback,
        AegisMessageNotifyCallback,
        1); // Maksimum eşzamanlı kullanıcı modu bağlantısı (AegisPC.Service)

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltCreateCommunicationPort hatasi: 0x%08X\n", status));
        UnregisterObjectCallbacks();
        PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // 8. Dosya I/O filtrelemeyi resmi olarak başlat
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltStartFiltering hatasi: 0x%08X\n", status));
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        UnregisterObjectCallbacks();
        PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Sürücü basariyla yüklendi: Minifilter, ProcessNotify ve ObCallbacks devrede.\n"));
    return STATUS_SUCCESS;
}

// ============================================================================
// SÜRÜCÜ BOŞALTMA (UNLOAD)
// ============================================================================

NTSTATUS AegisFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] AegisFilterUnload cagrildi. Kaynaklar temizleniyor...\n"));

    // 1. Sunucu iletişim portunu kapat
    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    // 2. ObRegisterCallbacks ve bildirim rutinlerini kaldır
    UnregisterObjectCallbacks();
    PsRemoveLoadImageNotifyRoutine(AegisImageLoadNotifyRoutine);
    PsSetCreateProcessNotifyRoutineEx(AegisProcessNotifyRoutine, TRUE);

    // 3. Filtre kaydını düşür
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Minifilter ve güvenlik rutinleri basariyla temizlendi.\n"));
    return STATUS_SUCCESS;
}

// ============================================================================
// INSTANCE KURULUM VE KALDIRMA GERİ ÇAĞIRIMLARI
// ============================================================================

NTSTATUS AegisInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    PAGED_CODE();

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Yeni birim instance'ina baglanildi (FS Type: %d)\n", VolumeFilesystemType));
    return STATUS_SUCCESS;
}

NTSTATUS AegisInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    return STATUS_SUCCESS;
}

VOID AegisInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
}

VOID AegisInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
}

// ============================================================================
// PRE-OPERATION CALLBACK: IRP_MJ_CREATE (PRE-EXEC & PRE-WRITE GATING)
// ============================================================================

FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PAEGIS_SCAN_REQUEST scanRequest = NULL;
    AEGIS_SCAN_RESPONSE scanResponse = { 0 };
    ULONG replyLength = sizeof(AEGIS_SCAN_RESPONSE);
    LARGE_INTEGER timeout;
    ULONG createDisposition;
    BOOLEAN isCreationAttempt;
    BOOLEAN isWriteOperation;
    ULONG currentPid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    PAGED_CODE();

    // 1. Çekirdek modu çağrılarını ve paging file işlemlerini atla
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 2. Kullanıcı modu servisi (AegisPC.Service) bağlı değilse fail-open
    if (gClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    currentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (currentPid <= 4 || (gProtectedPid != 0 && currentPid == gProtectedPid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // System veya kendi servisimiz bypass
    }

    // 3. Dosya creation ve write niyetlerini belirle
    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000FF;
    isCreationAttempt = (createDisposition == FILE_CREATE ||
                         createDisposition == FILE_OPEN_IF ||
                         createDisposition == FILE_OVERWRITE_IF ||
                         createDisposition == FILE_SUPERSEDE);

    isWriteOperation = (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
                        (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE)) != 0;

    // 4. Dosya adını güvenli ve normalize biçimde çek
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || nameInfo->Name.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 5. Havuzdan güvenli bellek tahsisi yap
    scanRequest = (PAEGIS_SCAN_REQUEST)AegisAllocatePaged(sizeof(AEGIS_SCAN_REQUEST));
    if (scanRequest == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(scanRequest, sizeof(AEGIS_SCAN_REQUEST));
    scanRequest->ProcessId = currentPid;
    scanRequest->IsWriteOperation = isWriteOperation;

    RtlCopyMemory(
        scanRequest->FilePath,
        nameInfo->Name.Buffer,
        min(nameInfo->Name.Length, (AEGIS_MAX_PATH_CHARS - 1) * sizeof(WCHAR)));
    scanRequest->FilePath[min(nameInfo->Name.Length / sizeof(WCHAR), AEGIS_MAX_PATH_CHARS - 1)] = L'\0';

    // 6. Ring-3 Kullanıcı Modu Servisine mesaj gönder (FltSendMessage, 200ms fail-open timeout)
    timeout.QuadPart = -2000000LL;

    status = FltSendMessage(
        gFilterHandle,
        &gClientPort,
        scanRequest,
        sizeof(AEGIS_SCAN_REQUEST),
        &scanResponse,
        &replyLength,
        &timeout);

    // 7. Karar Yönetimi: Kullanıcı modu tehdit tespit edip bloklama istedi mi?
    if (NT_SUCCESS(status) && scanResponse.BlockAccess) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, 
            "[AegisFilter] BLOKLANDI! Zararlı I/O engellendi. PID: %u, Dosya: %ws\n", 
            currentPid, scanRequest->FilePath));

        ExFreePoolWithTag(scanRequest, AEGIS_FILTER_TAG);
        FltReleaseFileNameInformation(nameInfo);

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    // 8. Post-Create takibi gerekiyorsa bağlam hazırla
    if (isCreationAttempt || isWriteOperation) {
        PAEGIS_PRE_2_POST_CONTEXT postContext = (PAEGIS_PRE_2_POST_CONTEXT)AegisAllocateNonPaged(sizeof(AEGIS_PRE_2_POST_CONTEXT));
        if (postContext != NULL) {
            postContext->IsCreationAttempt = isCreationAttempt;
            postContext->IsWriteOperation = isWriteOperation;
            postContext->ProcessId = currentPid;
            RtlCopyMemory(postContext->FilePath, scanRequest->FilePath, sizeof(postContext->FilePath));

            *CompletionContext = postContext;

            ExFreePoolWithTag(scanRequest, AEGIS_FILTER_TAG);
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    }

    ExFreePoolWithTag(scanRequest, AEGIS_FILTER_TAG);
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// PRE-OPERATION CALLBACK: IRP_MJ_WRITE (PRE-WRITE DATA PROTECTION)
// ============================================================================

FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PAEGIS_SCAN_REQUEST scanRequest = NULL;
    AEGIS_SCAN_RESPONSE scanResponse = { 0 };
    ULONG replyLength = sizeof(AEGIS_SCAN_RESPONSE);
    LARGE_INTEGER timeout;
    ULONG currentPid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    PAGED_CODE();

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (gClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    currentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (currentPid <= 4 || (gProtectedPid != 0 && currentPid == gProtectedPid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status) || nameInfo->Name.Length == 0) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    scanRequest = (PAEGIS_SCAN_REQUEST)AegisAllocatePaged(sizeof(AEGIS_SCAN_REQUEST));
    if (scanRequest == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(scanRequest, sizeof(AEGIS_SCAN_REQUEST));
    scanRequest->ProcessId = currentPid;
    scanRequest->IsWriteOperation = TRUE;

    RtlCopyMemory(
        scanRequest->FilePath,
        nameInfo->Name.Buffer,
        min(nameInfo->Name.Length, (AEGIS_MAX_PATH_CHARS - 1) * sizeof(WCHAR)));
    scanRequest->FilePath[min(nameInfo->Name.Length / sizeof(WCHAR), AEGIS_MAX_PATH_CHARS - 1)] = L'\0';

    timeout.QuadPart = -2000000LL; // 200 ms timeout

    status = FltSendMessage(
        gFilterHandle,
        &gClientPort,
        scanRequest,
        sizeof(AEGIS_SCAN_REQUEST),
        &scanResponse,
        &replyLength,
        &timeout);

    if (NT_SUCCESS(status) && scanResponse.BlockAccess) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, 
            "[AegisFilter] YAZMA İŞLEMİ BLOKLANDI! PID: %u, Dosya: %ws\n", 
            currentPid, scanRequest->FilePath));

        ExFreePoolWithTag(scanRequest, AEGIS_FILTER_TAG);
        FltReleaseFileNameInformation(nameInfo);

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ExFreePoolWithTag(scanRequest, AEGIS_FILTER_TAG);
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// POST-OPERATION CALLBACK: IRP_MJ_CREATE (FILE WRITE & CREATION MONITORING)
// ============================================================================

FLT_POSTOP_CALLBACK_STATUS AegisPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PAEGIS_PRE_2_POST_CONTEXT postContext = (PAEGIS_PRE_2_POST_CONTEXT)CompletionContext;
    UNREFERENCED_PARAMETER(FltObjects);

    if (FlagOn(Flags, FLTFL_CALLBACK_DATA_DRAINING)) {
        if (postContext != NULL) {
            ExFreePoolWithTag(postContext, AEGIS_FILTER_TAG);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (postContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (NT_SUCCESS(Data->IoStatus.Status)) {
        ULONG_PTR createResult = Data->IoStatus.Information;

        if (createResult == FILE_CREATED) {
            KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[AegisFilter] YENİ DOSYA OLUŞTURULDU: PID: %u, Dosya: %ws\n",
                postContext->ProcessId, postContext->FilePath));
        } else if (createResult == FILE_OVERWRITTEN || createResult == FILE_SUPERSEDED) {
            KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[AegisFilter] DOSYA ÜZERİNE YAZILDI: PID: %u, Dosya: %ws\n",
                postContext->ProcessId, postContext->FilePath));
        }
    }

    ExFreePoolWithTag(postContext, AEGIS_FILTER_TAG);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ============================================================================
// PRE-EXECUTION SÜREÇ YARATMA CALLBACK'İ (PsSetCreateProcessNotifyRoutineEx)
// ============================================================================

VOID AegisProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    // Süreç sonlanma bildirimi
    if (CreateInfo == NULL) {
        if (gProtectedPid != 0 && pid == gProtectedPid) {
            KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Korunan servis süreci kapandı.\n"));
            gProtectedPid = 0;
        }
        return;
    }

    // Süreç başlatma öncesi (Pre-Execution Gating)
    if (pid <= 4 || (gProtectedPid != 0 && pid == gProtectedPid)) {
        return;
    }

    if (gClientPort == NULL) {
        return; // User-mode bağlı değilse fail-open
    }

    if (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Length > 0) {
        AEGIS_SCAN_REQUEST scanReq;
        AEGIS_SCAN_RESPONSE scanResp = { 0 };
        ULONG replyLen = sizeof(AEGIS_SCAN_RESPONSE);
        LARGE_INTEGER timeout;
        NTSTATUS status;

        RtlZeroMemory(&scanReq, sizeof(AEGIS_SCAN_REQUEST));
        scanReq.ProcessId = pid;
        scanReq.IsWriteOperation = FALSE;

        ULONG copyLen = min(CreateInfo->ImageFileName->Length, (AEGIS_MAX_PATH_CHARS - 1) * sizeof(WCHAR));
        RtlCopyMemory(scanReq.FilePath, CreateInfo->ImageFileName->Buffer, copyLen);
        scanReq.FilePath[copyLen / sizeof(WCHAR)] = L'\0';

        timeout.QuadPart = -2000000LL; // 200 ms timeout

        status = FltSendMessage(
            gFilterHandle,
            &gClientPort,
            &scanReq,
            sizeof(AEGIS_SCAN_REQUEST),
            &scanResp,
            &replyLen,
            &timeout);

        if (NT_SUCCESS(status) && scanResp.BlockAccess) {
            KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[AegisFilter] ÇEKİRDEKTE SÜREÇ ENGELLEMESİ! STATUS_ACCESS_DENIED, PID: %u, İmaj: %ws\n",
                pid, scanReq.FilePath));
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        }
    }
}

// ============================================================================
// İMAJ / DİNAMİK KÜTÜPHANE YÜKLEME BİLDİRİMİ (PsSetLoadImageNotifyRoutine)
// ============================================================================

VOID AegisImageLoadNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    UNREFERENCED_PARAMETER(ProcessId);

    if (FullImageName == NULL || FullImageName->Length == 0) {
        return;
    }
}

// ============================================================================
// ÇEKİRDEK SELF-DEFENSE (ObRegisterCallbacks - HANDLE STRIPPING)
// ============================================================================

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

    // Korunan güvenlik servisi PID'si ise yetkileri kırp (Anti-Tamper Ring-0)
    if (targetPid == gProtectedPid && gProtectedPid != 0) {
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
            OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterObjectCallbacks(VOID)
{
    OB_CALLBACK_REGISTRATION callbackReg;
    OB_OPERATION_REGISTRATION opReg;

    RtlZeroMemory(&opReg, sizeof(opReg));
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = AegisPreOpenProcess;
    opReg.PostOperation = NULL;

    RtlZeroMemory(&callbackReg, sizeof(callbackReg));
    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = 1;
    RtlInitUnicodeString(&callbackReg.Altitude, L"320500");
    callbackReg.RegistrationContext = NULL;
    callbackReg.OperationRegistration = &opReg;

    return ObRegisterCallbacks(&callbackReg, &gObRegistrationHandle);
}

VOID UnregisterObjectCallbacks(VOID)
{
    if (gObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(gObRegistrationHandle);
        gObRegistrationHandle = NULL;
    }
}

// ============================================================================
// COMMUNICATION PORT GERİ ÇAĞIRIMLARI (PORT NOTIFY CALLBACKS)
// ============================================================================

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
    PAGED_CODE();

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Kullanıcı modu servisi baglandi (AegisPC.Service).\n"));

    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID AegisDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    PAGED_CODE();

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Kullanıcı modu baglantisi koptu.\n"));

    if (gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
        gClientPort = NULL;
    }
}

NTSTATUS AegisMessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    PAGED_CODE();

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    if (InputBuffer != NULL && InputBufferSize >= sizeof(AEGIS_CONTROL_COMMAND)) {
        PAEGIS_CONTROL_COMMAND cmd = (PAEGIS_CONTROL_COMMAND)InputBuffer;
        if (cmd->CommandCode == AEGIS_MSG_REGISTER_PROTECTED_PID) {
            gProtectedPid = cmd->ProcessId;
            KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, 
                "[AegisFilter] Korunan Servis PID kaydedildi: %u. ObRegisterCallbacks koruması devrede.\n", gProtectedPid));
            return STATUS_SUCCESS;
        }
    }

    return STATUS_SUCCESS;
}
