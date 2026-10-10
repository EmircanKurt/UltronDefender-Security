using System.Text.Json;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services;

/// <summary>Tray file-shield controls require two explicit approvals and fresh service observations; no local protection fallback.</summary>
public sealed class TrayProtectionActions(IServiceIpcClient ipc, IProtectionDisableConfirmation confirmation)
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Pauses only file protection through the administrator-authorized service; canceling either prompt sends no mutation.</summary>
    public async Task<bool> PauseAsync(int minutes, bool untilServiceRestart = false)
    {
        if (untilServiceRestart ? minutes != 0 : minutes is not (10 or 60 or 300)) throw new ArgumentOutOfRangeException(nameof(minutes));
        await _gate.WaitAsync();
        try
        {
            var before = await ipc.GetStatusAsync();
            if (!ServiceProtectionStatusPolicy.IsVerified(ipc, before) || before.RequestId == Guid.Empty || !before.SupportsTimedFileProtectionPause)
                throw new InvalidOperationException("Süreli duraklatma için güncel koruma hizmeti bağlı olmalı.");
            if (!before.IsRealTimeEnabled || before.FileProtectionPause != null)
                throw new InvalidOperationException("Dosya kalkanı zaten kapalı veya duraklatılmış.");
            var duration = untilServiceRestart ? "koruma hizmeti yeniden başlayana kadar" : $"{minutes} dakika";
            if (!await confirmation.ConfirmAsync("Dosya kalkanını duraklat?",
                $"Dosya kalkanı {duration} duracak. Bu sırada yeni veya değişen dosyalar bu katmanda incelenmez. Diğer kalkanlar ve Windows Defender kapatılmaz. Devam etmek istiyor musun?")) return false;
            if (!await confirmation.ConfirmAsync("Son onay",
                $"Dosya kalkanını {duration} duraklatmayı onaylıyor musun? Hizmet çalışır durumdaysa süre sonunda geri açılacak. 'Hayır' seçersen hiçbir değişiklik yapılmaz.")) return false;
            await ipc.SendCommandAsync(new ServiceCommand
            {
                CommandType = ServiceCommandType.PauseFileProtection, Timestamp = DateTime.UtcNow,
                Payload = JsonSerializer.Serialize(new { Minutes = minutes, ResumeOnServiceStart = untilServiceRestart })
            });
            var after = await ipc.GetStatusAsync();
            var pause = after.FileProtectionPause;
            if (!ServiceProtectionStatusPolicy.IsVerified(ipc, after) || after.RequestId == Guid.Empty || after.IsRealTimeEnabled || pause == null || pause.RestoreImmediately ||
                pause.ResumeOnServiceStart != untilServiceRestart || (!untilServiceRestart &&
                    (pause.ResumeAtUtc is not DateTime deadline || deadline < DateTime.UtcNow.AddMinutes(minutes - 1) || deadline > DateTime.UtcNow.AddMinutes(minutes + 1))))
                throw new InvalidOperationException("Duraklatma hizmet tarafından doğrulanmadı. Durumu yenile; yönetici yetkisi gerekebilir.");
            return true;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Requests manual restoration and confirms actual file listeners; it does not blindly enable every shield.</summary>
    public async Task ResumeAsync()
    {
        await _gate.WaitAsync();
        try
        {
            var status = await ServiceProtectionStatusPolicy.RequestChangeAsync(ipc, ransomware: false, enabled: true);
            if (status.FileProtectionPause != null) throw new InvalidOperationException("Süreli duraklatma kaydı henüz temizlenmedi; durumu yenile.");
        }
        finally { _gate.Release(); }
    }
}
