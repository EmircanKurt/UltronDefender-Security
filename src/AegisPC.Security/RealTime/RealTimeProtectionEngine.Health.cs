namespace AegisPC.Security.RealTime;

public partial class RealTimeProtectionEngine : IRealTimeCoverageProvider
{
    /// <summary>Samples registered roots and recovery/queue state without exposing user paths.</summary>
    public RealTimeCoverageSnapshot CaptureCoverage()
    {
        lock (_lock)
            return new RealTimeCoverageSnapshot(_watchers.Count, _coverageDegraded || _mediaInspections.Values.Any(x => x.State == "Partial"),
                _reconciliationRunning || _reconciliationRoots.Count > 0 || _mediaInspections.Values.Any(x => x.State is "Pending" or "Scanning"),
                _eventIngestor.PendingEventsCount, _eventIngestor.DroppedEventsCount);
    }
}
