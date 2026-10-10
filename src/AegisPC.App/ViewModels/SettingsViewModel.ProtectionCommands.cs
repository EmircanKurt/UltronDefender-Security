using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using AegisPC.App.Services;
using AegisPC.ServiceContracts.IpcMessages;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AegisPC.App.ViewModels;

public partial class SettingsViewModel
{
    private readonly SemaphoreSlim _serviceProtectionCommandGate = new(1, 1);
    private bool? _lastObservedFileProtection;
    private bool? _lastObservedRansomwareProtection;
    private bool _settingsDisposed;
    private ProtectionStatus? _lastProtectionStatus;
    private DispatcherTimer? _protectionStatusTimer;

    /// <summary>Whether the displayed protection booleans have a fresh service observation rather than a saved preference.</summary>
    [ObservableProperty] private bool isProtectionStatusVerified;

    private void StartProtectionStatusFreshnessCheck()
    {
        if (System.Windows.Application.Current?.Dispatcher is not { } dispatcher) return;
        _protectionStatusTimer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background,
            (_, _) =>
            {
                if (_settingsDisposed) return;
                IsProtectionStatusVerified = ServiceProtectionStatusPolicy.IsVerified(_ipcClient, _lastProtectionStatus);
                UpdateUltronAiObservation();
                EvaluateProtectionWarning();
            }, dispatcher);
        _protectionStatusTimer.Start();
    }

    private async Task RequestServiceProtectionChangeAsync(bool ransomware, bool enabled)
    {
        RestoreObservedProtectionToggles();
        await _serviceProtectionCommandGate.WaitAsync();
        try
        {
            if (_settingsDisposed) return;
            if (_ipcClient?.IsConnected != true)
            {
                IsProtectionStatusVerified = false;
                throw new InvalidOperationException("Koruma hizmeti bağlı değil; koruma ayarı değiştirilmedi veya yerel motor başlatılmadı.");
            }
            StatusMessage = "Koruma isteği doğrulanıyor; mevcut gözlenen durum korunuyor.";
            var status = await ServiceProtectionStatusPolicy.RequestChangeAsync(_ipcClient, ransomware, enabled);
            if (_settingsDisposed) return;
            ApplyServiceStatus(status);
            StatusMessage = "Hizmetin koruma durumu doğrulandı.";
            await LogAuditAsync(ransomware ? "Fidye Kalkanı" : "Dosya Kalkanı", enabled ? "Hizmette Etkin Olduğu Doğrulandı" : "Hizmette Kapalı Olduğu Doğrulandı");
        }
        catch (Exception exception)
        {
            if (_settingsDisposed) return;
            Serilog.Log.Warning(exception, "Service-owned settings protection change was not acknowledged");
            await RequestServiceStatusAsync();
            RestoreObservedProtectionToggles();
            StatusMessage = exception.Message;
        }
        finally
        {
            if (!_settingsDisposed) EvaluateProtectionWarning();
            _serviceProtectionCommandGate.Release();
        }
    }

    private void RestoreObservedProtectionToggles()
    {
        _isApplyingServiceStatus = true;
        try
        {
            IsFileProtectionEnabled = _lastObservedFileProtection ?? _settingsService?.Current.IsFileProtectionEnabled ?? false;
            IsRansomwareShieldEnabled = _lastObservedRansomwareProtection ?? _settingsService?.Current.IsRansomwareShieldEnabled ?? false;
            IsNetworkProtectionEnabled = _lastObservedNetworkProtection ?? _settingsService?.Current.IsNetworkProtectionEnabled ?? false;
        }
        finally { _isApplyingServiceStatus = false; }
    }
}
