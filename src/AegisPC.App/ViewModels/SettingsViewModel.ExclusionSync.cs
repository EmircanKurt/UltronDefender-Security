using System;
using System.Text.Json;
using System.Threading.Tasks;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.ViewModels;

/// <summary>Requests service refresh after local exclusion changes without misrepresenting transport delivery as an acknowledged security-policy update.</summary>
public partial class SettingsViewModel
{
    private async Task RefreshServiceExclusionsAsync()
    {
        if (_ipcClient?.IsConnected != true)
        {
            StatusMessage = "İstisna yerelde kaydedildi. Arka plan hizmeti bağlı değil; servis korumasına henüz uygulanmadı.";
            return;
        }
        try
        {
            await _ipcClient.SendCommandAsync(new ServiceCommand
            {
                CommandType = ServiceCommandType.UpdateSettings,
                Payload = JsonSerializer.Serialize(new { RefreshExclusions = true }),
                Timestamp = DateTime.UtcNow
            });
            StatusMessage = _ipcClient.IsConnected
                ? "Servise istisna yenileme isteği gönderildi; uygulandığı henüz doğrulanmadı (yönetici yetkisi gerekir)."
                : "İstisna kaydedildi ancak servis bağlantısı kesildi; yenileme uygulanmadı.";
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "Persisted exclusions could not be refreshed in the protection service.");
            StatusMessage = "İstisna yerelde kaydedildi, servis yenilemesi başarısız: " + ex.Message;
        }
    }
}
