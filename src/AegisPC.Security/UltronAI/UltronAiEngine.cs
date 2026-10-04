using System.Diagnostics;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.UltronAI;

/// <summary>Coordinates bounded local static review; not a trained model or an enforcement authority.</summary>
public sealed class UltronAiEngine : IUltronAiEngine
{
    /// <summary>Opens one read-only source and explicitly reports unreadable input.</summary>
    public async Task<UltronAiVerdict> EvaluateFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var source = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var classification = await new FileContentClassifier().ClassifyAsync(source, Path.GetExtension(filePath), cancellationToken);
            return await EvaluateLockedFileAsync(source, filePath, classification, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return new UltronAiVerdict { PrimaryDiagnosis = "İnceleme tamamlanamadı", CoverageLimitations = new() { "InputUnavailable" },
                ReasoningDeduction = "Dosya okunamadı; temiz veya zararlı kararı verilemedi." };
        }
    }

    /// <summary>Uses structural identity and the same locked bytes regardless of path or extension.</summary>
    public Task<UltronAiVerdict> EvaluateLockedFileAsync(Stream source, string filePath,
        FileContentClassification classification, CancellationToken cancellationToken = default)
    {
        var clock = Stopwatch.StartNew();
        var verdict = EvaluateVector(UltronFeatureExtractor.Extract(source, filePath, classification, cancellationToken));
        verdict.InferenceTimeMs = clock.Elapsed.TotalMilliseconds;
        return Task.FromResult(verdict);
    }

    /// <summary>Produces review priority only; missing data never becomes a clean-file claim.</summary>
    public UltronAiVerdict EvaluateVector(UltronFeatureVector vector)
    {
        var clock = Stopwatch.StartNew();
        if (vector == null) return new() { PrimaryDiagnosis = "Veri eksik", CoverageLimitations = new() { "MissingFeatureVector" } };
        if (!float.IsFinite(vector.EntropyOverall) || vector.EntropyOverall is < 0 or > 8 ||
            !float.IsFinite(vector.DangerousApiRatio) || vector.DangerousApiRatio is < 0 or > 1 ||
            vector.FileSizeBytes < 0 || vector.SectionCount < 0 || vector.TotalImportsCount < 0)
            return new() { PrimaryDiagnosis = "Geçersiz özellik verisi", CoverageLimitations = new() { "InvalidFeatureVector" } };
        var verdict = UltronCognitiveBrain.Reason(vector, UltronDecisionEnsemble.Predict(vector));
        verdict.InferenceTimeMs = clock.Elapsed.TotalMilliseconds;
        return verdict;
    }
}
