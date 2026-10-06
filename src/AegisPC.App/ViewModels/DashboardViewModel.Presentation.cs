using AegisPC.App.Services;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;

namespace AegisPC.App.ViewModels;

public partial class DashboardViewModel
{
    /// <summary>Current observed availability, independent of scan findings and desired switches.</summary>
    public DashboardProtectionPresentation DashboardPresentation => DashboardProtectionPresentation.Create(
        _observedServiceStatus, _ipcClient?.IsConnected == true, DateTime.UtcNow);

    /// <summary>Requests status without enabling a protection or changing a setting.</summary>
    [RelayCommand]
    public async Task RefreshProtectionStatusAsync()
    {
        try
        {
            if (_ipcClient?.IsConnected != true)
            {
                ApplyServiceStatus(null);
                TriggerToast("Arka plan hizmetine bağlanılamadı. Korumalar bölümünü kontrol edin.", "Info");
                return;
            }
            OnServiceStatusChanged(await _ipcClient.GetStatusAsync());
        }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Dashboard status refresh failed");
            _observedServiceStatus = null;
            OnUi(() => ApplyServiceStatus(null));
        }
    }

    /// <summary>Routes full scans through the existing resource-selection and session flow.</summary>
    [RelayCommand]
    public async Task StartFullScanAsync()
    {
        var scanVm = App.ServiceProvider?.GetService<ScanViewModel>();
        if (scanVm == null)
        {
            TriggerToast("Tarayıcı hizmeti hazır değil; tarama başlatılamadı.", "Warning");
            return;
        }
        try { await scanVm.StartFullScanAsync(); }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Dashboard full scan request failed");
            TriggerToast("Tarama başlatılamadı. Tarama bölümündeki ayrıntıları kontrol edin.", "Warning");
        }
    }
}
