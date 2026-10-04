using System;
using System.Threading.Tasks;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services;

/// <summary>Requires fresh authenticated-service observations instead of optimistic UI protection state.</summary>
internal static class ServiceProtectionStatusPolicy
{
    internal static bool IsVerified(IServiceIpcClient? ipc, ProtectionStatus? status) =>
        ipc?.IsConnected == true && status?.IsServiceRunning == true && status.Health?.IsFresh(DateTime.UtcNow) == true;

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
