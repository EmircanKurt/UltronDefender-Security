using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using AegisPC.ServiceContracts;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels;

/// <summary>Shows observed service scope and explicit pilot limitations; never invents Guardian health or successful actions.</summary>
public partial class UltronProtectionCentreViewModel : ObservableObject
{
    private readonly IServiceIpcClient _ipc;
    private readonly IBehaviorEngine _behavior;
    /// <summary>Opens the existing authenticated protection settings flow without changing a switch.</summary>
    [RelayCommand]
    public void OpenProtectionSettings() => AppNavigation.NavigateTo(typeof(AegisPC.App.Views.SettingsView));
    /// <summary>Constructs a read-only centre over the existing service transport and observation source.</summary>
    public UltronProtectionCentreViewModel(IServiceIpcClient ipc, IBehaviorEngine behavior) { _ipc = ipc; _behavior = behavior; }
    /// <summary>Explains current observed protection scope.</summary>
    [ObservableProperty] private string protectionStatus = "Doğrulanmadı; güncel hizmet sağlığı gerekli.";
    /// <summary>Reports observer and event-loss state, separately from desired settings.</summary>
    [ObservableProperty] private string coverageStatus = "Henüz güncel hizmet verisi yok.";
    /// <summary>Reports actual local observation count, never a virus count.</summary>
    [ObservableProperty] private string evidenceStatus = "Davranış gözlemleri henüz yüklenmedi.";
    /// <summary>Reports passive remote observation separately from the unopened connection-denial pilot.</summary>
    [ObservableProperty] private string remoteLayerStatus = "Uzak erişim gözlemi için güncel hizmet verisi yok. Otomatik RDP reddi açık değil.";
    /// <summary>Reports passive wireless inventory coverage; unavailable permissions do not imply safe radios.</summary>
    [ObservableProperty] private string wirelessLayerStatus = "Wi-Fi/Bluetooth gözlem verisi yok. Ağ veya aygıt kapatma yapılmaz.";
    /// <summary>Explains that the filter is an audit prototype, not validated pre-access malware prevention.</summary>
    public string FilterLayerStatus => "Ultron Filter: gözlem prototipi. İmzalı sürücü ve VM kapısı tamamlanmadı; ön-erişim engelleme yayımlanmadı.";
    /// <summary>Exposes the migration and native identity gate rather than presenting a prototype as emergency protection.</summary>
    public string GuardianStatus => "Guardian prototipi: bağımsız hizmet/kasa devri ve çok kullanıcılı VM pilotu bekliyor. Acil otomatik müdahale açık değil.";
    /// <summary>Separates review from permissions and receipts.</summary>
    public string ActionStatus => "Ultron AI statik ve davranış puanı yalnız inceleme önceliğidir. Onay/müdahale/geri alma hattı Guardian doğrulaması bitmeden açılmaz.";
    /// <summary>Refreshes observed health on demand; no background timer or native intervention is created by this page.</summary>
    [RelayCommand]
    public async Task RefreshAsync()
    {
        RemoteLayerStatus = "Uzak erişim için güncel gözlem alınmadı. Otomatik RDP reddi açık değil.";
        WirelessLayerStatus = "Wi-Fi/Bluetooth için güncel gözlem alınmadı. Ağ veya aygıt kapatma yapılmaz.";
        try
        {
            EvidenceStatus = $"{(await _behavior.GetActiveIncidentsAsync()).Count} yerel davranış gözlemi; servis genelindeki olayların tamamı değil. Zararlılık doğrulanmış sayılmaz.";
            if (!_ipc.IsConnected) { ProtectionStatus = "Hizmet bağlı değil; koruma doğrulanmadı."; CoverageStatus = "Güncel veri yok."; return; }
            var status = await _ipc.GetStatusAsync();
            if (status.Health?.IsFresh(DateTime.UtcNow) != true)
            { ProtectionStatus = "Sağlık verisi eksik veya bayat; etkinlik doğrulanmadı."; CoverageStatus = "Güncel veri yok."; return; }
            ProtectionStatus = $"Son sorgu ({DateTime.UtcNow:HH:mm:ss} UTC): {status.Health.State}. Anlık durum değildir; yenilemeden etkinlik garantisi vermez. Defender yanında olay-sonrası ek koruma.";
            CoverageStatus = $"{status.Health.WatcherCount} kök; {status.Health.ManagedEventsLost} dosya / {status.Health.OperatingSystemEventsLost} ETW olay kaybı. " +
                string.Join(" ", status.Health.Limitations.Take(6));
            RemoteLayerStatus = $"Uzak giriş: {ObservationLabel(status.Health.RemoteObservationState)}; konsol ölçümü: {ObservationLabel(status.Health.ConsoleObservationState)}. Yalnız olay-sonrası gözlem; yeni bağlantı engellenmez.";
            WirelessLayerStatus = $"Wi-Fi: {ObservationLabel(status.Health.WifiObservationState)}; Bluetooth Classic: {ObservationLabel(status.Health.BluetoothObservationState)}. Firmware, BLE ve sahte ağ engelleme doğrulanmadı.";
        }
        catch (Exception ex)
        { Serilog.Log.Warning(ex, "Protection centre health request failed."); ProtectionStatus = "Hizmet sağlığı alınamadı; etkinlik doğrulanmadı."; CoverageStatus = "Bağlantı/istek hatası."; }
    }

    private static string ObservationLabel(string state) => state switch
    { "Available" => "metaveri gözlendi", "Partial" => "kısmi metaveri", "Unavailable" => "kullanılamıyor", _ => "henüz veri yok" };
}
