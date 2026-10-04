using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.Input;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.ViewModels;

public partial class DashboardViewModel
{
    /// <summary>Exports authorized observed identity/functions and initial-media coverage; never firmware authenticity.</summary>
    [RelayCommand]
    public async Task ExportDeviceInventoryAsync()
    {
        try
        {
            if (_ipcClient?.IsConnected != true || _ipcClient is not IServiceRequestClient client)
                throw new IOException("Güncel aygıt raporu için koruma hizmeti gerekli.");
            var reply = await client.RequestAsync(ServiceCommandType.GetDeviceInventory);
            if (!reply.Success || string.IsNullOrWhiteSpace(reply.Payload))
                throw new InvalidOperationException("Aygıt raporu alınamadı; yönetici yetkisi gerekebilir. " + reply.Code);
            if (Application.Current == null) return;
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "USB / HID ve Medya İnceleme Raporu",
                FileName = "Ultron_AygitRaporu_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".json",
                Filter = "JSON raporu (*.json)|*.json", DefaultExt = ".json", RestoreDirectory = true
            };
            if (dialog.ShowDialog(Application.Current.MainWindow) != true) return;
            await File.WriteAllTextAsync(dialog.FileName, reply.Payload, System.Text.Encoding.UTF8);
            TriggerToast("Aygıt gözlem raporu kaydedildi. Firmware güvenliği doğrulanmış değildir.", "Info");
        }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Observed device report could not be exported.");
            TriggerToast(exception.Message, "Warning");
        }
    }
}
