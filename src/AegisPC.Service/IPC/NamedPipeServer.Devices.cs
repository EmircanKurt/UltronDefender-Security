using AegisPC.Core.Models.Devices;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.Service.IPC;

public partial class NamedPipeServer
{
    private readonly object _deviceNoticeLock = new();
    private readonly Dictionary<string, DeviceFunction> _observedFunctions = new(StringComparer.OrdinalIgnoreCase);
    private bool _deviceBaseline;

    private void OnDeviceSnapshotChanged(DeviceInventorySnapshot snapshot)
    {
        // PresenceComplete describes volume membership, not HID capabilities.
        // Incomplete queries cannot remove known functions or establish a new baseline.
        if (!snapshot.IsComplete) return;
        lock (_deviceNoticeLock)
        {
            var functions = snapshot.Devices.Where(d => d.UsbAssociation == UsbAssociation.Usb)
                .GroupBy(d => d.ContainerId?.ToString("N") ?? d.InstanceId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.Aggregate(DeviceFunction.Unknown, (value, d) => value | d.Functions), StringComparer.OrdinalIgnoreCase);
            if (_deviceBaseline)
                foreach (var current in functions)
                {
                    bool known = _observedFunctions.TryGetValue(current.Key, out var previous);
                    bool addedKeyboard = current.Value.HasFlag(DeviceFunction.Keyboard) && (!known || !previous.HasFlag(DeviceFunction.Keyboard));
                    bool changed = known && previous != current.Value;
                    if (!addedKeyboard && !changed) continue;
                    bool composite = current.Value.HasFlag(DeviceFunction.Storage) && current.Value.HasFlag(DeviceFunction.Keyboard);
                    BroadcastMessage("Device", new DeviceNotice
                    {
                        CompositeStorageKeyboard = composite,
                        Message = composite ? "USB aygıtı hem depolama hem klavye işlevi sunuyor. Bu bir gözlemdir, zararlı hükmü değildir."
                            : addedKeyboard ? "Yeni USB klavye işlevi algılandı. Aygıt kimliği firmware güvenliğini kanıtlamaz."
                            : "Bir USB aygıtının sunduğu işlevler değişti. Değişim tek başına zararlı kanıtı değildir."
                    });
                }
            _observedFunctions.Clear();
            foreach (var current in functions) _observedFunctions[current.Key] = current.Value;
            _deviceBaseline = true;
        }
    }
}
