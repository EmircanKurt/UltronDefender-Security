using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>
/// Compatibility entry points for the local persistence inspector. This component does not run
/// Microsoft MRT/MSRT, remove persistence, inspect unbacked memory, or establish malware certainty.
/// </summary>
public static class MsrtRemediationEngine
{
    /// <summary>Reads local configuration and returns review findings; cancellation propagates.</summary>
    public static Task<List<SecurityFinding>> RunMsrtDeepScanAsync(
        IProgress<string>? phaseReporter = null, CancellationToken cancellationToken = default) =>
        SystemPersistenceInspector.ScanAsync(phaseReporter, cancellationToken);

    /// <summary>Returns existing executable targets from readable autorun entries without changing the registry.</summary>
    public static List<string> GetPersistenceTargetPaths() => SystemPersistenceInspector.GetPersistenceTargetPaths();

    // Retained for existing decision-only regression fixtures; the actual classifier is shared with the inspector.
    private static SecurityFinding? CreateTemporaryProcessFinding(string mainModule, string processName, int processId) =>
        SystemPersistenceEvidenceClassifier.Evaluate(new SystemPersistenceObservation
        {
            Kind = SystemPersistenceObservationKind.TemporaryProcess,
            ObjectPath = mainModule,
            ObjectName = processName,
            Value = mainModule,
            ProcessId = processId
        });
}
