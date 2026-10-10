using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using System.Security.Cryptography;

namespace AegisPC.Security.Scanning;

/// <summary>Compatibility adapter to the shared decision pipeline; legacy heuristics never run as a fallback.</summary>
public sealed class RiskScoringEngine : IRiskScoringEngine
{
    private readonly IDetectionHub? _detectionHub;

    /// <summary>Preserves the legacy constructor while accepting the shared engine from the composition root.</summary>
    public RiskScoringEngine(ILocalReputationService? localReputationService = null, IDetectionHub? detectionHub = null)
    {
        _detectionHub = detectionHub;
    }

    /// <summary>Unproven hash registrations cannot establish either malware or optional-tool classification.</summary>
    public static void RegisterPupHash(string sha256) { }

    /// <summary>No verified optional-tool catalog is configured in the legacy compatibility surface.</summary>
    public static bool IsKnownPupHash(string? sha256) => false;

    /// <summary>Returns an explicit unknown result if the shared engine is unavailable; cancellation propagates.</summary>
    public async Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(
        FileAnalysisResult result, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        cancellationToken.ThrowIfCancellationRequested();
        if (_detectionHub == null)
            return (0, RiskLevel.Unknown, ["SharedDetectionEngineUnavailable: legacy name/location/hash heuristics disabled."]);

        try
        {
            await using var source = new FileStream(result.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
            string hash = Convert.ToHexString(await SHA256.HashDataAsync(source, cancellationToken));
            if (result.SHA256 != null && !string.Equals(hash, result.SHA256, StringComparison.OrdinalIgnoreCase) ||
                result.FileSize > 0 && result.FileSize != source.Length)
                return (0, RiskLevel.Unknown, ["FileIdentityChanged: legacy analysis no longer identifies current content."]);
            source.Position = 0;
            var classification = await new FileContentClassifier().ClassifyAsync(source, Path.GetExtension(result.FilePath), cancellationToken);
            var context = new DetectionContext
            {
                FilePath = result.FilePath, SHA256 = hash, FileSize = source.Length, ContentClassification = classification,
                SharedScan = new ScanContext(result.FilePath, hash, source.Length) { LockedContent = source, ContentClassification = classification }
            };
            context.CoverageLimitations.AddRange(classification.CoverageLimitations);
            return MapDecision(await _detectionHub.EvaluateAsync(context, cancellationToken));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Serilog.Log.Warning(ex, "Legacy shared-engine adapter could not verify the source.");
            return (0, RiskLevel.Unknown, ["FileInspectionUnavailable: current source could not be verified."]);
        }
    }

    private static (int score, RiskLevel level, List<string> reasons) MapDecision(DetectionResult decision)
    {
        var level = decision.Verdict switch
        {
            DetectionVerdict.Clean => RiskLevel.Clean,
            DetectionVerdict.LowRisk => RiskLevel.LowRisk,
            DetectionVerdict.Suspicious => RiskLevel.Suspicious,
            DetectionVerdict.HighRisk => RiskLevel.HighRisk,
            DetectionVerdict.ConfirmedMalicious => RiskLevel.ConfirmedMalicious,
            _ => RiskLevel.Unknown
        };
        return (decision.RiskScore, level, decision.Evidences.Select(e => e.Description)
            .Concat(decision.CoverageLimitations).ToList());
    }
}
