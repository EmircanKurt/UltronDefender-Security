using AegisPC.Contracts.Detection;
using AegisPC.Security.Scanning;
using AegisPC.Security.UltronAI;

namespace AegisPC.Security.Detection.Detectors;

/// <summary>Routes content-based local review without file-name trust or duplicate static scoring.</summary>
public sealed class UltronAiDetectorPlugin : IDetectorPlugin
{
    /// <summary>Stable plugin identifier.</summary>
    public string DetectorId => "Detector.UltronAI";
    /// <summary>Describes deterministic local review honestly.</summary>
    public string DisplayName => "Ultron AI yerel statik inceleme";
    /// <summary>Preserves the persisted legacy category ordinal.</summary>
    public EvidenceCategory PrimaryCategory => EvidenceCategory.MachineLearningHeuristic;
    /// <summary>Runs after authoritative hash/provider inspection.</summary>
    public int Priority => 35;
    /// <summary>Keeps this routing plugin registered so disabled review can clear stale context; the live review preference is separate.</summary>
    public bool IsEnabled { get; set; } = true;
    private readonly IUltronAiEngine _engine;
    private readonly Func<bool> _isReviewEnabled;
    /// <summary>Reports the wired optional-review preference, not an active watcher or independent protection capability.</summary>
    public bool IsReviewEnabled => IsEnabled && _isReviewEnabled();
    /// <summary>Accepts a review engine and a live optional-review preference, never an action authority; omitted preferences preserve existing callers.</summary>
    public UltronAiDetectorPlugin(IUltronAiEngine? aiEngine = null, Func<bool>? isReviewEnabled = null)
    {
        _engine = aiEngine ?? new UltronAiEngine();
        _isReviewEnabled = isReviewEnabled ?? (() => true);
    }

    /// <summary>Uses the borrowed locked source where available; legacy calls also hold one source throughout review.</summary>
    public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(context);
        ClearReviewResult(context);
        if (!IsReviewEnabled) return Array.Empty<SecurityEvidence>();
        long policyRevision = DetectionPolicyRevision.Current;
        var source = context.SharedScan?.LockedContent;
        UltronAiVerdict verdict;
        if (source != null)
        {
            var classification = context.ContentClassification ??
                await new FileContentClassifier().ClassifyAsync(source, Path.GetExtension(context.FilePath), cancellationToken);
            verdict = await _engine.EvaluateLockedFileAsync(source, context.FilePath, classification, cancellationToken);
        }
        else verdict = await _engine.EvaluateFileAsync(context.FilePath, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        // A toggle or another policy change during an awaited analysis cannot publish stale review metadata.
        if (!IsReviewEnabled || policyRevision != DetectionPolicyRevision.Current)
            return Array.Empty<SecurityEvidence>();
        context.Properties["UltronAiVerdict"] = verdict;
        context.Properties["UltronAiReviewPriority"] = verdict.CalculatedRiskScore;
        context.Properties.Remove("UltronAiProbability");
        if (verdict.Coverage != AegisPC.Core.Models.ContentClassificationCoverage.Complete)
            foreach (var limitation in verdict.CoverageLimitations.DefaultIfEmpty("UltronStaticReviewIncomplete").Take(16))
                context.CoverageLimitations.Add("UltronStaticReview: " + limitation);
        // Existing PE/entropy/API detectors already own these features. Do not count them as independent AI evidence.
        return Array.Empty<SecurityEvidence>();
    }

    private static void ClearReviewResult(DetectionContext context)
    {
        context.Properties.Remove("UltronAiVerdict");
        context.Properties.Remove("UltronAiReviewPriority");
        context.Properties.Remove("UltronAiProbability");
        context.CoverageLimitations.RemoveAll(item => item.StartsWith("UltronStaticReview: ", StringComparison.Ordinal));
    }
}
