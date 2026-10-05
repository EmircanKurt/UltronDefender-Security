using AegisPC.Core.Models;
using AegisPC.Security.RealTime;

namespace AegisPC.Service.IPC;

/// <summary>Combines observed listener state, never desired settings alone, into supplemental protection health.</summary>
internal static class ProtectionHealthSampler
{
    /// <summary>Produces path-free status; unavailable coverage and ETW subscription cannot become healthy.</summary>
    internal static ProtectionHealthSnapshot Capture(bool desiredEnabled, bool fileListenersActive,
        RealTimeCoverageSnapshot? coverage, bool processSubscribed, bool imagePumpActive,
        long osEventsLost, bool lifecycleHealthy, bool kernelConnected, bool ransomwareActive)
    {
        var reasons = new List<string>();
        if (coverage == null) reasons.Add("Filesystem coverage could not be sampled.");
        else
        {
            if (coverage.WatcherCount == 0) reasons.Add("No filesystem roots are watched.");
            if (coverage.HasPersistentGap) reasons.Add("Filesystem coverage contains unresolved gaps.");
            if (coverage.RecoveryPending) reasons.Add("Filesystem reconciliation is pending.");
        }
        if (!processSubscribed) reasons.Add("Process post-start telemetry is unavailable.");
        if (!imagePumpActive) reasons.Add("Image-load telemetry is unavailable.");
        if (osEventsLost != 0) reasons.Add("ETW event continuity is unavailable or has historical loss.");
        if (!lifecycleHealthy) reasons.Add("A protection transition did not complete successfully.");
        if (!ransomwareActive) reasons.Add("Ransomware observation is not active.");
        bool gap = !fileListenersActive || coverage == null || coverage.WatcherCount == 0 ||
            coverage.HasPersistentGap || !processSubscribed || !imagePumpActive ||
            osEventsLost != 0 || !lifecycleHealthy;
        return new ProtectionHealthSnapshot
        {
            CapturedAtUtc = DateTime.UtcNow,
            State = !desiredEnabled ? ProtectionHealthState.Stopped : gap ? ProtectionHealthState.Degraded
                : coverage!.RecoveryPending ? ProtectionHealthState.Recovering : ProtectionHealthState.Healthy,
            WatcherCount = coverage?.WatcherCount ?? 0,
            PendingFileEvents = coverage?.PendingEvents ?? 0,
            RecoveryPending = coverage?.RecoveryPending ?? false,
            ManagedEventsLost = coverage?.LostEvents ?? 0,
            FileWatcherErrors = coverage?.WatcherErrors ?? 0,
            OperatingSystemEventsLost = osEventsLost,
            ProcessTelemetryActive = processSubscribed,
            ImageTelemetryActive = imagePumpActive,
            KernelBridgeConnected = kernelConnected,
            // API support and a started hosts helper are not a connected content/flow inspection pipeline.
            AmsiContentScanningActive = false,
            NetworkFlowInspectionActive = false,
            Limitations = reasons.ToArray()
        };
    }
}

