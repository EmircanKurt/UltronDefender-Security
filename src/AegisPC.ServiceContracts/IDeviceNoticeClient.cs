using System;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.ServiceContracts;

/// <summary>Additional device observations, separate from threat detections.</summary>
public interface IDeviceNoticeClient
{
    /// <summary>New USB keyboard or changed function; does not indicate confirmed malware.</summary>
    event Action<DeviceNotice>? DeviceObserved;
}
