using AegisPC.Core.Models;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services;

/// <summary>A readable protection row, not an enforcement or malware verdict.</summary>
public sealed record DashboardProtectionRow(string Name, string State);

/// <summary>Pure presentation derived only from current service observations.</summary>
public sealed record DashboardProtectionPresentation(string Title, string Detail,
    IReadOnlyList<DashboardProtectionRow> Rows)
{
    /// <summary>Rejects absent, incompatible, future and stale observations.</summary>
    public static DashboardProtectionPresentation Create(ProtectionStatus? status, bool connected, DateTime utcNow)
    {
        var health = status?.Health;
        bool fresh = connected && status?.IsServiceRunning == true && health?.IsFresh(utcNow) == true;
        if (!fresh)
            return new("Koruma durumu alınamadı",
                "Arka plan hizmetinden güncel bilgi yok. Durumu yenileyin veya Korumalar bölümünü açın.",
                [new("Gerçek zamanlı izleme", "Bilgi yok"), new("Ultron AI", "Bilgi yok"),
                 new("Fidye kalkanı", "Bilgi yok"), new("USB / HID", "Bilgi yok"),
                 new("Browser Defender", "İstek üzerine inceleme")]);

        string rt = !status!.IsRealTimeEnabled ? "Kapalı" : health!.State switch
        {
            ProtectionHealthState.Healthy when health.WatcherCount > 0 => "İzleme etkin",
            ProtectionHealthState.Recovering => "Yeniden bağlanıyor",
            ProtectionHealthState.Stopped => "Durduruldu",
            _ => "Kapsam sınırlı"
        };
        string ai = status.IsUltronAiEnabled switch
        {
            false => "Kapalı",
            true when health!.BehaviorObservationActive => "Davranış gözlemi etkin",
            true => "Yerel inceleme açık",
            _ => "Bilgi yok"
        };
        string ransom = !status.IsRansomwareShieldEnabled ? "Kapalı" :
            status.RansomwareProtectedFolderCount > 0 && status.RansomwareCanaryFileCount > 0
                ? "Gözlem etkin" : "Kapsam alınamadı";
        bool inventoryFresh = health!.DeviceInventoryCapturedAtUtc is { } captured &&
            captured != default && utcNow >= captured && utcNow - captured <= TimeSpan.FromSeconds(15);
        string usb = !inventoryFresh ? "Bilgi yok" : health.DeviceInventoryActive && health.DeviceInventoryComplete
            ? "Gözlem etkin" : "Kapsam sınırlı";
        string title = rt == "İzleme etkin" ? "Gerçek zamanlı izleme etkin" : "Koruma durumunu inceleyin";
        string detail = rt == "İzleme etkin"
            ? $"{health.WatcherCount} konum izleniyor. Bu, bütün bilgisayarın temiz olduğu anlamına gelmez."
            : "Bazı korumalar kapalı veya sınırlı. Ayrıntıları Korumalar bölümünde görebilirsiniz.";
        if (health.RecoveryPending || health.ManagedEventsLost > 0 || health.FileWatcherErrors > 0 ||
            health.OperatingSystemEventsLost > 0)
        {
            title = "İzleme kapsamını inceleyin";
            detail = "İzlemede olay kaybı veya kurtarma bildirildi. Korumalar bölümünde ayrıntıları inceleyin.";
        }
        return new(title, detail, [new("Gerçek zamanlı izleme", rt), new("Ultron AI", ai),
            new("Fidye kalkanı", ransom), new("USB / HID", usb), new("Browser Defender", "İstek üzerine inceleme")]);
    }
}
