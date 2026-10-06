using AegisPC.Contracts.Protection;
using AegisPC.Core.Models;

namespace AegisPC.Service.IPC;

public partial class NamedPipeServer
{
    private readonly IRemoteProtectionMonitor? _remoteObservation;
    private readonly IWirelessProtectionMonitor? _wirelessObservation;
    private readonly AegisPC.Service.Workers.PassiveSecurityObservationWorker? _passiveWorker;

    private void AddPassiveHealth(ProtectionHealthSnapshot health)
    {
        bool running = _passiveWorker?.IsObservationLoopRunning == true;
        var remote = _remoteObservation?.CurrentSnapshot;
        bool remoteFresh = running && _settingsService.GetSetting("EnableRemoteObservation", true) && Fresh(remote?.CapturedAtUtc);
        health.RemoteObservationState = remoteFresh ? remote!.LogonAvailability.ToString() : "Unavailable";
        health.ConsoleObservationState = remoteFresh ? remote!.ConsoleAvailability.ToString() : "Unavailable";
        // Do not expose another user's console presence, account SID, source addresses or proposed denial details.
        health.RemoteNativeEnforcementActive = false;
        var wireless = _wirelessObservation?.CurrentSnapshot.Inventory;
        bool wirelessFresh = running && _settingsService.GetSetting("EnableWirelessObservation", true) && Fresh(wireless?.CapturedAtUtc);
        health.WifiObservationState = wirelessFresh ? wireless!.WifiAvailability.ToString() : "Unavailable";
        health.BluetoothObservationState = wirelessFresh ? wireless!.BluetoothAvailability.ToString() : "Unavailable";
        health.PassiveObservationCapturedAtUtc = remoteFresh ? remote!.CapturedAtUtc : null;
        health.WirelessNativeEnforcementActive = false;
    }

    private static bool Fresh(DateTime? captured) => captured is { Kind: DateTimeKind.Utc } value &&
        value != default && value <= DateTime.UtcNow && DateTime.UtcNow - value <= TimeSpan.FromSeconds(15);
}
