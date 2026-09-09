#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Minifilter callbacks do not require encoded function pointers")

// ============================================================================
// SABITLER VE BELLEK HAVUZU TANIMLARI
// ============================================================================

#define AEGIS_FILTER_TAG          'sgeA'          // Bellek etiketimiz: 'Aegs'
#define AEGIS_PORT_NAME           L"\\AegisFilterPort"
#define AEGIS_MAX_PATH_CHARS      512

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

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT   gServerPort   = NULL;
PFLT_PORT   gClientPort   = NULL;

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
#pragma alloc_text(PAGE, AegisConnectNotifyCallback)
#pragma alloc_text(PAGE, AegisDisconnectNotifyCallback)
#pragma alloc_text(PAGE, AegisMessageNotifyCallback)

// ============================================================================
// MINIFILTER OPERASYON VE KAYIT TABLOLARI (FLT_REGISTRATION)
// ============================================================================

// Yakalanacak dosya sistemi I/O işlemleri (Pre/Post Callbacks)
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        AegisPreCreate,
        AegisPostCreate
    },
    { IRP_MJ_OPERATION_END }
};

// Minifilter kayıt yapısı
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

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] DriverEntry baslatiliyor...\n"));

    // 1. Minifilter sürücüsünü Filtre Yöneticisine (Filter Manager) kaydet
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltRegisterFilter hatasi: 0x%08X\n", status));
        return status;
    }

    // 2. İletişim portu için varsayılan güvenlik tanımlayıcısını oluştur
    // Bu işlem, yalnızca Yöneticilerin (Administrators) ve LocalSystem hesabının porta bağlanabilmesini sağlar
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltBuildDefaultSecurityDescriptor hatasi: 0x%08X\n", status));
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // 3. İletişim Portu nesne niteliklerini ilklendir
    RtlInitUnicodeString(&portName, AEGIS_PORT_NAME);
    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        sd);

    // 4. Çift yönlü filtre iletişim portunu oluştur (\AegisFilterPort)
    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &oa,
        NULL,
        AegisConnectNotifyCallback,
        AegisDisconnectNotifyCallback,
        AegisMessageNotifyCallback,
        1); // Maksimum eşzamanlı kullanıcı modu bağlantısı (AegisPC.Service)

    // Güvenlik tanımlayıcısını serbest bırak (Port oluşturulduktan sonra gerek kalmaz)
    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltCreateCommunicationPort hatasi: 0x%08X\n", status));
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // 5. Dosya I/O filtrelemeyi resmi olarak başlat
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[AegisFilter] FltStartFiltering hatasi: 0x%08X\n", status));
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Sürücü basariyla yüklendi ve filtreleme aktif.\n"));
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

    // 2. Filtre kaydını düşür (Bu çağrı tüm instance'ları ve bekleyen I/O'ları güvenle sonlandırır)
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Minifilter basariyla kaldirildi.\n"));
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

    // Sadece desteklenen dosya sistemlerine bağlan (NTFS, ReFS, FAT, vb.)
    // Sanal veya geçici cihazları filtrelemeye gerek yoktur
    if (VolumeFilesystemType == FLT_FSTYPE_MUP ||
        VolumeFilesystemType == FLT_FSTYPE_UNKNOWN) {
        // İsteğe bağlı olarak ağ paylaşımları da taranabilir
    }

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

    // fltmc detach komutlarına ve dinamik ayrılmaya izin ver
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

    // 1. Çekirdek modu çağrılarını ve paging file işlemlerini atla (Deadlock / Paging I/O koruması)
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 2. Kullanıcı modu servisi (AegisPC.Service) porta bağlı değilse I/O akışını kesme (Fail-open)
    if (gClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    currentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (currentPid <= 4) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // System (PID 4) bypass
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
        // Dosya adı çözülemezse açılış adını dene
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

    // 5. Havuzdan güvenli bellek tahsisi yap (ExAllocatePool2 / IRQL safe paged pool)
    scanRequest = (PAEGIS_SCAN_REQUEST)AegisAllocatePaged(sizeof(AEGIS_SCAN_REQUEST));
    if (scanRequest == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // Bellek yetersizliğinde sistemi kilitleme
    }

    RtlZeroMemory(scanRequest, sizeof(AEGIS_SCAN_REQUEST));
    scanRequest->ProcessId = currentPid;
    scanRequest->IsWriteOperation = isWriteOperation;

    // Dosya yolunu sınırları taşmayacak şekilde kopyala
    RtlCopyMemory(
        scanRequest->FilePath,
        nameInfo->Name.Buffer,
        min(nameInfo->Name.Length, (AEGIS_MAX_PATH_CHARS - 1) * sizeof(WCHAR)));
    scanRequest->FilePath[min(nameInfo->Name.Length / sizeof(WCHAR), AEGIS_MAX_PATH_CHARS - 1)] = L'\0';

    // 6. Ring-3 Kullanıcı Modu Servisine mesaj gönder (FltSendMessage)
    // 200 ms timeout: Kullanıcı modu geç yanıt verse dahi sistem kilitlenmesini (hang) önler
    timeout.QuadPart = -2000000LL; // 200 ms (100-nanosaniyelik birimler)

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

        // Bellekleri temizle ve işlemi STATUS_ACCESS_DENIED ile durdur
        AegisAllocatePaged(0); // Dummy çağrı önleme
        ExFreePoolWithTag(scanRequest, AEGIS_FILTER_TAG);
        FltReleaseFileNameInformation(nameInfo);

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    // 8. Eğer dosya yazma veya yeni oluşturma ise, Post-Create aşamasında izlemek için context hazırla
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

    // Draining kontrolü: Filtre kaldırılıyorsa hemen çık
    if (FlagOn(Flags, FLTFL_CALLBACK_DATA_DRAINING)) {
        if (postContext != NULL) {
            ExFreePoolWithTag(postContext, AEGIS_FILTER_TAG);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Bağlam yoksa veya I/O başarısız olduysa temizle ve dön
    if (postContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Dosya başarıyla oluşturuldu mu veya üzerine yazıldı mı?
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

    // Post-op bağlam belleğini serbest bırak
    ExFreePoolWithTag(postContext, AEGIS_FILTER_TAG);
    return FLT_POSTOP_FINISHED_PROCESSING;
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

    // Kullanıcı modu istemci portunu sakla
    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID AegisDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    PAGED_CODE();

    KdPrintEx((DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[AegisFilter] Kullanıcı modu baglantisi koptu.\n"));

    // İstemci portunu kapat ve sıfırla
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
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    PAGED_CODE();

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    // Kullanıcı modundan gelen doğrudan kontrol mesajları için genişletilebilir
    return STATUS_SUCCESS;
}
