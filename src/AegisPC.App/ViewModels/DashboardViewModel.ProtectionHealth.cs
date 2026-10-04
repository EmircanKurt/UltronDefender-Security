using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Core.Models;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.ViewModels;

public partial class DashboardViewModel
{
    private void OnDeviceObserved(DeviceNotice notice) => OnUi(() => TriggerToast(notice.Message, "Info"));
    private Timer? _protectionHealthTimer;
    private ProtectionStatus? _observedServiceStatus;
    private bool _applyingServiceStatus;
    private readonly SemaphoreSlim _protectionCommandGate = new(1, 1);

    private void OnServiceStatusChanged(ProtectionStatus status)
    {
        _observedServiceStatus = status;
        OnUi(() => ApplyServiceStatus(status));
    }

    private void CheckProtectionFreshness()
    {
        var status = _observedServiceStatus;
        if (status?.Health?.IsFresh(DateTime.UtcNow) == true && _ipcClient?.IsConnected == true) return;
        OnUi(() => ApplyServiceStatus(status));
    }

    private static void OnUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess()) dispatcher.InvokeAsync(action);
        else action();
    }

    private void ApplyServiceStatus(ProtectionStatus? status)
    {
        bool connected = _ipcClient?.IsConnected == true && status?.IsServiceRunning == true;
        var health = status?.Health;
        bool fresh = connected && health?.IsFresh(DateTime.UtcNow) == true;
        _applyingServiceStatus = true;
        try
        {
            IsServiceConnected = connected;
            IsRealTimeProtectionActive = fresh && status!.IsRealTimeEnabled &&
                health!.State == ProtectionHealthState.Healthy;
            IsRansomwareEnabled = fresh && status!.IsRansomwareShieldEnabled;
            UpdateRansomwareStateTexts(IsRansomwareEnabled);
            RealTimeHealthStatus = !fresh ? "Doğrulanmadı" : health!.State switch
            {
                ProtectionHealthState.Healthy => "Kapsam dahilinde etkin",
                ProtectionHealthState.Recovering => "Yeniden inceleniyor",
                ProtectionHealthState.Stopped => "Durduruldu",
                _ => "Kısıtlı"
            };
            RealTimeHealthMessage = !fresh ? "Güncel hizmet durumu yok; eski veya yerel ayarlar koruma kanıtı değildir"
                : $"{health!.WatcherCount} izleme kökü; {health.PendingFileEvents} bekleyen olay; " +
                  $"{health.ManagedEventsLost} dosya / {health.OperatingSystemEventsLost} ETW olay kaybı. " +
                  (health.State == ProtectionHealthState.Healthy ? "Olay-sonrası kullanıcı modu koruma; ön-erişim engelleme değildir."
                      : string.Join(" ", health.Limitations.Take(4)));
            RealTimeHealthColor = IsRealTimeProtectionActive ? "#4CAF50" : "#F5A623";
            WatcherStatusText = fresh ? $"{health!.WatcherCount} kök" : "Doğrulanmadı";
            EventQueueStatusText = fresh ? $"{health!.PendingFileEvents} bekliyor" : "Doğrulanmadı";
            QuarantineStatusText = connected ? "Hizmet üzerinden" : "Hizmet gerekli";
            EngineArchitectureText = fresh
                ? $"Dosya izleme / süreç ETW: {(health!.ProcessTelemetryActive ? "etkin" : "kısıtlı")}; AMSI içerik: {(health.AmsiContentScanningActive ? "etkin" : "bağlı değil")}" : "Modül kapsamı doğrulanmadı";
            if (fresh) EngineArchitectureText += $"; USB/HID: {(health!.DeviceInventoryActive && health.DeviceInventoryComplete ? "gözlem etkin" : "kısıtlı")}";
            if (connected) ThreatsBocked24h = status!.TotalThreatsBlocked24h;
            if (!IsScanning && !HasThreatsDetected)
            {
                ProtectionStatusText = RealTimeHealthStatus;
                ProtectionBadgeText = fresh ? status!.ProtectionLevel : "Hizmet bağlantısı veya sağlık verisi eksik";
                ProtectionStatusColor = RealTimeHealthColor;
            }
        }
        finally { _applyingServiceStatus = false; }
    }

    private async Task RequestProtectionCommandAsync(ServiceCommandType command, bool? ransomwareTarget = null)
    {
        await _protectionCommandGate.WaitAsync();
        try
        {
            if (_ipcClient?.IsConnected != true) throw new InvalidOperationException("Koruma hizmeti bağlı değil.");
            await _ipcClient.SendCommandAsync(new ServiceCommand { CommandType = command, Timestamp = DateTime.UtcNow });
            var status = await _ipcClient.GetStatusAsync();
            OnServiceStatusChanged(status);
            bool acknowledged = status.Health?.IsFresh(DateTime.UtcNow) == true && status.IsServiceRunning &&
                (ransomwareTarget.HasValue ? status.IsRansomwareShieldEnabled == ransomwareTarget.Value :
                    status.IsRealTimeEnabled == (command == ServiceCommandType.EnableProtection));
            if (!acknowledged) throw new InvalidOperationException("İstenen durum hizmet tarafından doğrulanmadı; yönetici yetkisi gerekebilir.");
            OnUi(() => TriggerToast("Hizmetin koruma durumu doğrulandı.", "Info"));
        }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Service-owned protection command was not acknowledged");
            OnUi(() => { ApplyServiceStatus(_observedServiceStatus); TriggerToast(exception.Message, "Warning"); });
        }
        finally { _protectionCommandGate.Release(); }
    }
}
