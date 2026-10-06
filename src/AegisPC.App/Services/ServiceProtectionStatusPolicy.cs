using System;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services;

/// <summary>Requires fresh authenticated-service observations instead of optimistic UI protection state.</summary>
internal static class ServiceProtectionStatusPolicy
{
    internal static bool IsVerified(IServiceIpcClient? ipc, ProtectionStatus? status) =>
        ipc?.IsConnected == true && status?.IsServiceRunning == true && status.Health?.IsFresh(DateTime.UtcNow) == true;

    /// <summary>Describes observed availability without presenting missing or expired observations as a license or threat error.</summary>
    internal static ServiceProtectionNotice Describe(IServiceIpcClient? ipc, ProtectionStatus? status, DateTime utcNow)
    {
        if (ipc?.IsConnected != true)
            return new("Arka plan korumasına bağlanılamadı",
                "Kalkanların çalışma durumu alınamadı. Ayarlar son kaydedilen tercihler olabilir. Yenile ile tekrar deneyin.");
        if (status?.IsServiceRunning != true)
            return new("Arka plan koruması yanıt vermiyor",
                "Kalkanların çalışma durumu alınamadı. Yenile ile tekrar deneyin.");
        var health = status.Health;
        if (health == null || health.ProtocolVersion != 1)
            return new("Koruma bilgisi alınamadı",
                "Uygulama ve arka plan hizmeti farklı sürümlerde olabilir. Sürüm uyumluluğunu kontrol edip Yenile ile tekrar deneyin.");
        if (!health.IsFresh(utcNow))
            return new("Koruma bilgisi güncel değil",
                "Son durum 15 saniyeden eski veya zamanı geçersiz. Kalkanların güncel çalışma durumu için Yenile ile tekrar deneyin.");
        if (!status.IsRealTimeEnabled || !status.IsRansomwareShieldEnabled || status.IsUltronAiEnabled == false)
            return new("Koruma katmanlarından bazıları kapalı",
                "Kapalı katmanlar dosyaları incelemez. Kalkan ayarlarını ve diğer güvenlik uygulamanızın durumunu kontrol edin.",
                ServiceProtectionNoticeSeverity.Warning);
        return health.State switch
        {
            ProtectionHealthState.Healthy => new(string.Empty, string.Empty),
            ProtectionHealthState.Recovering => new("Koruma izlemesi yenileniyor",
                "Arka plan koruması izleme kapsamını yeniden kuruyor. Güncel durum için Yenile ile tekrar kontrol edin."),
            ProtectionHealthState.Degraded => new("Koruma kapsamı kısmi",
                "Bazı izleme bileşenleri kullanılamıyor; kapsam kısmi. Ayrıntıları Ultron AI Koruma Merkezi'nde inceleyin.",
                ServiceProtectionNoticeSeverity.Warning),
            ProtectionHealthState.Stopped => new("Dosya koruması durduruldu",
                "Arka plan hizmeti dosya izlemesinin durduğunu bildiriyor. Kalkan ayarlarını kontrol edip Yenile ile tekrar deneyin.",
                ServiceProtectionNoticeSeverity.Warning),
            _ => new("Koruma çalışma durumu bilinmiyor",
                "Arka plan hizmeti çalışma durumunu bildirmedi. Yenile ile tekrar deneyin.")
        };
    }

    internal static async Task<ProtectionStatus> RequestChangeAsync(IServiceIpcClient? ipc, bool ransomware, bool enabled)
    {
        if (ipc?.IsConnected != true)
            throw new InvalidOperationException("Koruma hizmeti bağlı değil; durum değişikliği doğrulanamadı.");

        var command = ransomware
            ? enabled ? ServiceCommandType.EnableRansomwareShield : ServiceCommandType.DisableRansomwareShield
            : enabled ? ServiceCommandType.EnableProtection : ServiceCommandType.DisableProtection;
        await ipc.SendCommandAsync(new ServiceCommand { CommandType = command, Timestamp = DateTime.UtcNow });
        var status = await ipc.GetStatusAsync();
        if (!IsVerified(ipc, status) || status.RequestId == Guid.Empty ||
            (ransomware ? status.IsRansomwareShieldEnabled : status.IsRealTimeEnabled) != enabled)
            throw new InvalidOperationException("İstenen durum hizmet tarafından doğrulanmadı; yönetici yetkisi gerekebilir. İstek uygulanmış olabilir.");
        return status;
    }

    internal static async Task<ProtectionStatus> RequestUltronAiChangeAsync(IServiceIpcClient? ipc, bool enabled)
    {
        if (ipc?.IsConnected != true)
            throw new InvalidOperationException("Protection service is disconnected.");
        await ipc.SendCommandAsync(new ServiceCommand
        {
            CommandType = enabled ? ServiceCommandType.EnableUltronAi : ServiceCommandType.DisableUltronAi,
            Timestamp = DateTime.UtcNow
        });
        var status = await ipc.GetStatusAsync();
        if (!IsVerified(ipc, status) || status.RequestId == Guid.Empty || status.IsUltronAiEnabled != enabled)
            throw new InvalidOperationException("Optional AI review change has no fresh matching service acknowledgement.");
        return status;
    }

    internal static async Task<ProtectionStatus> RequestNetworkChangeAsync(IServiceIpcClient? ipc, bool enabled)
    {
        if (ipc?.IsConnected != true) throw new InvalidOperationException("Protection service is disconnected.");
        await ipc.SendCommandAsync(new ServiceCommand
        {
            CommandType = enabled ? ServiceCommandType.EnableNetworkProtection : ServiceCommandType.DisableNetworkProtection,
            Timestamp = DateTime.UtcNow
        });
        var status = await ipc.GetStatusAsync();
        if (!IsVerified(ipc, status) || status.RequestId == Guid.Empty || status.IsNetworkProtectionEnabled != enabled)
            throw new InvalidOperationException("Network helper change has no fresh matching service acknowledgement.");
        return status;
    }
}

/// <summary>Distinguishes unavailable status information from an observed protection limitation.</summary>
internal enum ServiceProtectionNoticeSeverity { Information, Warning }

/// <summary>Plain-language status copy; an empty title means no notice is required for the current observation.</summary>
internal readonly record struct ServiceProtectionNotice(string Title, string Message,
    ServiceProtectionNoticeSeverity Severity = ServiceProtectionNoticeSeverity.Information);
