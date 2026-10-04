using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Security.RealTime;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels;

/// <summary>Presents service-observed ransomware monitoring; it never owns local watchers or canaries.</summary>
public partial class RansomwareShieldViewModel : ObservableObject, IDisposable
{
    private readonly IServiceIpcClient? _ipc;
    private readonly IWindowsToastNotificationService? _toastService;
    private readonly DispatcherTimer? _freshnessTimer;
    private ProtectionStatus? _observedStatus;
    private bool _disposed;

    [ObservableProperty] private bool _isShieldEnabled;
    [ObservableProperty] private bool _isStatusVerified;
    [ObservableProperty] private string _shieldStatusText = "Fidye izleme durumu doğrulanmadı — koruma hizmeti gerekli";
    [ObservableProperty] private string _toggleButtonText = "Hizmet Durumunu Yenile";
    [ObservableProperty] private string _statusMessage = "Klasör ve izin yönetimi bu sürümde yetkili hizmet uç noktası olmadığı için kullanılamıyor.";
    [ObservableProperty] private int _canaryFileCount;
    [ObservableProperty] private int _protectedFolderCount;
    [ObservableProperty] private int _totalBlockedCount;
    [ObservableProperty] private string _canaryFileCountText = "Doğrulanmadı";
    [ObservableProperty] private string _protectedFolderCountText = "Doğrulanmadı";
    [ObservableProperty] private string _totalBlockedCountText = "Doğrulanmadı";
    [ObservableProperty] private ObservableCollection<ProtectedFolder> _protectedFolders = new();
    [ObservableProperty] private ObservableCollection<AllowedRansomwareApplication> _allowedApplications = new();
    [ObservableProperty] private ObservableCollection<RansomwareEvent> _recentEvents = new();

    /// <summary>Legacy engine/settings parameters are accepted for compatibility but are never read or started locally.</summary>
    public RansomwareShieldViewModel(IRansomwareProtectionEngine? ransomwareEngine = null,
        SettingsService? settingsService = null, IWindowsToastNotificationService? toastService = null,
        IServiceIpcClient? ipcClient = null)
    {
        _ipc = ipcClient;
        _toastService = toastService;
        if (_ipc != null) _ipc.StatusChanged += ObserveStatus;
        if (Application.Current?.Dispatcher is { } dispatcher)
        {
            _freshnessTimer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background,
                OnFreshnessTick, dispatcher);
            _freshnessTimer.Start();
        }
        _ = RefreshStatusAsync();
    }

    private void OnFreshnessTick(object? sender, EventArgs args)
    {
        if (!ServiceProtectionStatusPolicy.IsVerified(_ipc, _observedStatus)) MarkUnverified();
    }

    private void ObserveStatus(ProtectionStatus status) => OnUi(() =>
    {
        if (_disposed) return;
        _observedStatus = status;
        if (!ServiceProtectionStatusPolicy.IsVerified(_ipc, status)) { MarkUnverified(); return; }
        IsStatusVerified = true;
        IsShieldEnabled = status.IsRansomwareShieldEnabled;
        ProtectedFolderCount = Math.Max(0, status.RansomwareProtectedFolderCount ?? 0);
        CanaryFileCount = Math.Max(0, status.RansomwareCanaryFileCount ?? 0);
        TotalBlockedCount = Math.Max(0, status.RansomwareConfirmedContainments ?? 0);
        ProtectedFolderCountText = FormatCount(status.RansomwareProtectedFolderCount);
        CanaryFileCountText = FormatCount(status.RansomwareCanaryFileCount);
        TotalBlockedCountText = FormatCount(status.RansomwareConfirmedContainments);
        ShieldStatusText = IsShieldEnabled
            ? status.Health!.State == ProtectionHealthState.Healthy
                ? "Hizmetin kullanıcı modu fidye gözlemi etkin — ön-yazma engelleme değildir"
                : "Hizmette fidye gözlemi etkin; koruma kapsamı kısmi veya kurtarılıyor"
            : "Hizmetin fidye gözlemi devre dışı";
        ToggleButtonText = IsShieldEnabled ? "İzlemeyi Kapat" : "İzlemeyi Etkinleştir";
    });

    private static string FormatCount(int? count) => count.HasValue && count.Value >= 0 ? count.Value.ToString() : "Doğrulanmadı";

    private void MarkUnverified()
    {
        IsStatusVerified = false;
        IsShieldEnabled = false;
        CanaryFileCount = ProtectedFolderCount = TotalBlockedCount = 0;
        CanaryFileCountText = ProtectedFolderCountText = TotalBlockedCountText = "Doğrulanmadı";
        ShieldStatusText = "Fidye izleme durumu doğrulanmadı — güncel hizmet yanıtı gerekli";
        ToggleButtonText = "Hizmet Durumunu Yenile";
    }

    private async Task RefreshStatusAsync()
    {
        if (_disposed) return;
        try
        {
            if (_ipc?.IsConnected != true) { OnUi(MarkUnverified); return; }
            ObserveStatus(await _ipc.GetStatusAsync());
        }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Ransomware service observation could not be refreshed");
            OnUi(() => { MarkUnverified(); StatusMessage = "Hizmet yanıtı doğrulanamadı; koruma durumu bilinmiyor."; });
        }
    }

    [RelayCommand]
    private async Task ToggleShieldAsync()
    {
        if (_disposed) return;
        if (!ServiceProtectionStatusPolicy.IsVerified(_ipc, _observedStatus))
        {
            await RefreshStatusAsync();
            OnUi(() => StatusMessage = IsStatusVerified ? "Hizmet durumu yenilendi; değiştirmek için tekrar seçin." : "Hizmet bağlı değil veya durumu doğrulanamadı; değişiklik yapılmadı.");
            return;
        }

        bool enabled = !_observedStatus!.IsRansomwareShieldEnabled;
        try
        {
            var status = await ServiceProtectionStatusPolicy.RequestChangeAsync(_ipc, ransomware: true, enabled);
            ObserveStatus(status);
            OnUi(() =>
            {
                StatusMessage = "Hizmetin fidye izleme durumu doğrulandı.";
                _toastService?.ShowToast("Fidye İzleme", StatusMessage, "Info");
            });
        }
        catch (Exception exception)
        {
            Serilog.Log.Warning(exception, "Service-owned ransomware command was not acknowledged");
            await RefreshStatusAsync();
            OnUi(() => { StatusMessage = exception.Message; _toastService?.ShowToast("Durum Doğrulanamadı", StatusMessage, "Warning"); });
        }
    }

    [RelayCommand] private void AddFolder() => ReportManagementUnavailable();
    [RelayCommand] private void RemoveFolder(ProtectedFolder? folder) => ReportManagementUnavailable();
    [RelayCommand] private void AddAllowedApp() => ReportManagementUnavailable();
    [RelayCommand] private void RemoveAllowedApp(AllowedRansomwareApplication? app) => ReportManagementUnavailable();

    private void ReportManagementUnavailable()
    {
        StatusMessage = "Yetkili hizmette klasör/izin yönetimi uç noktası bulunmuyor; hiçbir liste veya dosya değiştirilmedi.";
        _toastService?.ShowToast("Yönetim Kullanılamıyor", StatusMessage, "Warning");
    }

    private void OnUi(Action action)
    {
        if (_disposed) return;
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess()) dispatcher.InvokeAsync(() => { if (!_disposed) action(); });
        else action();
    }

    /// <summary>Removes UI metadata subscriptions without modifying service protection.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_ipc != null) _ipc.StatusChanged -= ObserveStatus;
        _freshnessTimer?.Stop();
    }
}

/// <summary>Detached folder display data; no UI instance grants filesystem protection.</summary>
public class ProtectedFolder
{
    /// <summary>Display path.</summary>
    public string Path { get; set; } = string.Empty;
    /// <summary>Display name.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Observed protection only when backed by an authorized service list.</summary>
    public bool IsProtected { get; set; }
    /// <summary>Measured size, never a fabricated sample.</summary>
    public long SizeBytes { get; set; }
}

/// <summary>Detached incident display data; a finding is not proof that an action succeeded.</summary>
public class RansomwareEvent
{
    /// <summary>Observed incident time.</summary>
    public DateTime Timestamp { get; set; }
    /// <summary>Observed process label.</summary>
    public string ProcessName { get; set; } = string.Empty;
    /// <summary>Authorized display path.</summary>
    public string FilePath { get; set; } = string.Empty;
    /// <summary>Confirmed action description.</summary>
    public string Action { get; set; } = string.Empty;
}
