using System;
using System.Threading.Tasks;
using AegisPC.App.Services;

namespace AegisPC.App.ViewModels;

public partial class SettingsViewModel
{
    private bool? _lastObservedNetworkProtection;

    private async Task RequestNetworkProtectionChangeAsync(bool enabled)
    {
        RestoreObservedProtectionToggles();
        await _serviceProtectionCommandGate.WaitAsync();
        try
        {
            if (_settingsDisposed) return;
            StatusMessage = "DNS/ağ ayarı hizmette doğrulanıyor; mevcut gözlenen durum korunuyor.";
            var status = await ServiceProtectionStatusPolicy.RequestNetworkChangeAsync(_ipcClient, enabled);
            if (_settingsDisposed) return;
            ApplyServiceStatus(status);
            StatusMessage = enabled
                ? "Hizmetin DNS/ağ yardımcı katmanını açtığı doğrulandı; tüm ağ akışı incelemesi değildir."
                : "Hizmetin DNS/ağ yardımcı katmanını kapattığı doğrulandı.";
            await LogAuditAsync("DNS/ağ yardımcı katmanı", enabled ? "Hizmette açık doğrulandı" : "Hizmette kapalı doğrulandı");
        }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Network helper configuration change was not acknowledged");
            if (!_settingsDisposed)
            {
                await RequestServiceStatusAsync();
                RestoreObservedProtectionToggles();
                StatusMessage = "DNS/ağ değişikliği doğrulanamadı; hizmet bağlantısını ve yönetici yetkisini kontrol edin.";
            }
        }
        finally { _serviceProtectionCommandGate.Release(); }
    }
}
