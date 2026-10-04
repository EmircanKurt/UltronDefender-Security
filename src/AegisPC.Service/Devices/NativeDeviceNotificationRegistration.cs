using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using AegisPC.Core.Models.Devices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Devices;

/// <summary>Owns native callback roots until successful unregister, including partial-registration cleanup.</summary>
internal sealed class NativeDeviceNotificationRegistration : IDisposable
{
    private static readonly ConcurrentBag<NativeDeviceNotificationRegistration> FailedUnregistrations = new();
    private readonly WindowsDeviceNative.NotificationCallback _callback;
    private readonly Action<DeviceDiscoverySignal> _onSignal;
    private readonly ILogger? _logger;
    private readonly List<IntPtr> _registrations = new();
    private int _disposed;

    internal NativeDeviceNotificationRegistration(Action<DeviceDiscoverySignal> onSignal, ILogger? logger)
    {
        _onSignal = onSignal;
        _logger = logger;
        _callback = OnNativeNotification;
        try
        {
            foreach (var guid in new[] { WindowsDeviceNative.DiskInterface, WindowsDeviceNative.HidInterface })
            {
                var filter = new WindowsDeviceNative.NotificationFilter
                { Size = (uint)Marshal.SizeOf<WindowsDeviceNative.NotificationFilter>(), ClassGuid = guid };
                uint result = WindowsDeviceNative.CM_Register_Notification(ref filter, IntPtr.Zero, _callback, out var handle);
                if (result != 0) throw new Win32Exception((int)result, "PnP notification registration failed.");
                _registrations.Add(handle);
            }
        }
        catch { Dispose(); throw; }
    }

    private uint OnNativeNotification(IntPtr registration, IntPtr context, uint action, IntPtr data, uint bytes)
    {
        if (Volatile.Read(ref _disposed) != 0 || data == IntPtr.Zero || bytes < 26 || action > 1) return 0;
        try
        {
            // CM_NOTIFY_EVENT_DATA: FilterType/Reserved, ClassGuid, bounded WCHAR symbolic link.
            if (Marshal.ReadInt32(data) != 0) return 0;
            int characters = (int)Math.Min((bytes - 24) / 2, 4096);
            string path = Marshal.PtrToStringUni(data + 24, characters)?.Split('\0')[0] ?? string.Empty;
            _onSignal(new DeviceDiscoverySignal
            {
                Kind = action == 0 ? DeviceDiscoverySignalKind.Arrival : DeviceDiscoverySignalKind.Removal,
                InterfacePath = path
            });
        }
        catch (Exception exception) { _logger?.LogWarning(exception, "PnP callback metadata was rejected."); }
        return 0; // Observation only: no query-remove veto or device action.
    }

    /// <summary>Runs outside callbacks; native unregister waits for in-flight callback completion.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        bool failed = false;
        foreach (var handle in _registrations)
        {
            uint result = WindowsDeviceNative.CM_Unregister_Notification(handle);
            if (result == 0) continue;
            failed = true;
            _logger?.LogError("Could not unregister PnP callback ({Result}); callback root retained and disabled.", result);
        }
        if (failed) FailedUnregistrations.Add(this); // Never release a delegate still reachable by native code.
        GC.KeepAlive(_callback);
    }
}
