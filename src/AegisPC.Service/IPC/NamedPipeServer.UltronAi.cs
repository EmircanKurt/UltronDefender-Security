using AegisPC.Security;
using AegisPC.Security.Detection.Detectors;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.IPC;

/// <summary>Persists authenticated optional-review controls without changing mandatory detectors or native action policy.</summary>
public partial class NamedPipeServer
{
    private readonly SemaphoreSlim _ultronAiReviewPolicyLock = new(1, 1);

    private async Task SetUltronAiReviewEnabledAsync(bool enabled)
    {
        if (_detectionHub?.RegisteredDetectors.OfType<UltronAiDetectorPlugin>().Any() != true)
            throw new InvalidOperationException("Optional Ultron AI review is unavailable in this service instance.");
        await _ultronAiReviewPolicyLock.WaitAsync().ConfigureAwait(false);
        bool previous = _settingsService.Current.IsUltronAiEnabled;
        try
        {
            _settingsService.Current.IsUltronAiEnabled = enabled;
            DetectionPolicyRevision.Invalidate();
            await _settingsService.SaveAsync().ConfigureAwait(false);
            _logger.LogInformation("Optional Ultron AI static review configuration saved: {Enabled}. Mandatory detectors and action validation are unchanged.", enabled);
        }
        catch (Exception exception)
        {
            _settingsService.Current.IsUltronAiEnabled = previous;
            DetectionPolicyRevision.Invalidate();
            _logger.LogWarning(exception, "Optional Ultron AI preference could not be persisted; the previous runtime preference was restored.");
            throw;
        }
        finally { _ultronAiReviewPolicyLock.Release(); }
    }
}
