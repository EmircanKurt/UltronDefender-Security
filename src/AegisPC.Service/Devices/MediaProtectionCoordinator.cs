using AegisPC.Core.Models.Devices;
using AegisPC.Security.RealTime;

namespace AegisPC.Service.Devices;

/// <summary>Connects identity/generation discovery to the common service-owned file pipeline.</summary>
internal sealed class MediaProtectionCoordinator(IRealTimeProtectionEngine protection)
{
    internal Task InspectAsync(MediaVolumeSession session, CancellationToken token)
    {
        if (protection is not IRemovableMediaProtection media)
            throw new InvalidOperationException("The file engine does not support initial media inspection.");
        return media.InspectMediaAsync(session.Volume.VolumeGuid, session.Generation, token);
    }

    internal Task RemoveAsync(MediaVolumeSession session)
    {
        (protection as IRemovableMediaProtection)?.RemoveMedia(session.Generation);
        return Task.CompletedTask;
    }
}
