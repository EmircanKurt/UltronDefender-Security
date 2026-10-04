using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Detection.Detectors;

/// <summary>
/// Sends bounded, strictly decoded text to the installed AMSI provider without executing it.
/// Provider verdicts, administrative policy, local hints and incomplete coverage remain distinct.
/// This is post-event content inspection, not a registered script-host interception provider.
/// </summary>
public sealed class AmsiContentDetector : IDetectorPlugin
{
    private const int MaximumContentBytes = 1024 * 1024;
    private const int NativeMalwareThreshold = 32768;
    private readonly IAmsiScanService _amsi;
    private readonly IFileContentClassifier _classifier;

    /// <summary>Identifies this shared content detector independently of its display text.</summary>
    public string DetectorId => "Detector.AmsiContent";
    /// <summary>Describes installed-provider content inspection, not independent Ultron interception.</summary>
    public string DisplayName => "Native AMSI Content Inspection";
    /// <summary>Separates provider verdicts from exact local hash signatures.</summary>
    public EvidenceCategory PrimaryCategory => EvidenceCategory.AmsiProvider;
    /// <summary>Runs after exact hash checks and before static script heuristics.</summary>
    public int Priority => 21;
    /// <summary>Controls participation in the configured shared pipeline.</summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>Uses the supplied provider and structural classifier; the detector does not own or register the provider.</summary>
    public AmsiContentDetector(IAmsiScanService amsiScanService, IFileContentClassifier? classifier = null)
    {
        _amsi = amsiScanService ?? throw new ArgumentNullException(nameof(amsiScanService));
        _classifier = classifier ?? new FileContentClassifier();
    }

    /// <summary>Reads under a non-mutating file lock; the calling scan session must hold its identity lock across all detectors.</summary>
    public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var observed = context.ContentClassification ?? context.SharedScan?.ContentClassification;
        if (observed != null && !IsTextCandidate(observed)) return new[] { NotApplicable(context) };
        try
        {
            using var source = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await EvaluateContentAsync(context, source, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new[] { Coverage(context, "AMSI content source could not be read under a stable file lock.") };
        }
    }

    /// <summary>
    /// Inspects a caller-owned readable seekable stream and restores its position, including on cancellation.
    /// The caller retains ownership and must prevent concurrent mutation; this seam permits inert in-memory tests.
    /// </summary>
    public async Task<IEnumerable<SecurityEvidence>> EvaluateContentAsync(DetectionContext context, Stream source,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(source);
        cancellationToken.ThrowIfCancellationRequested();
        if (!source.CanRead || !source.CanSeek)
            return new[] { Coverage(context, "AMSI content inspection requires a readable seekable source.") };
        long original = source.Position;
        try
        {
            var classification = context.ContentClassification ?? context.SharedScan?.ContentClassification;
            if (classification == null)
            {
                classification = await _classifier.ClassifyAsync(source, Path.GetExtension(context.FilePath), cancellationToken);
                context.ContentClassification = classification;
                if (context.SharedScan != null) context.SharedScan.ContentClassification = classification;
                foreach (string reason in classification.CoverageLimitations) AddCoverage(context, reason);
            }
            if (!IsTextCandidate(classification)) return new[] { NotApplicable(context) };
            if (source.Length > MaximumContentBytes)
                return new[] { Coverage(context, "AMSI text inspection omitted content exceeding its 1 MiB byte budget.") };
            source.Position = 0;
            byte[] bytes = new byte[checked((int)source.Length)];
            await source.ReadExactlyAsync(bytes.AsMemory(), cancellationToken);
            string text;
            try { text = DecodeStrict(bytes); }
            catch (DecoderFallbackException)
            { return new[] { Coverage(context, "AMSI text inspection could not strictly decode the complete input as UTF-8 or BOM-marked UTF-16.") }; }
            if (text.Length == 0)
                return new[] { Fact(context, "Amsi.EmptyContent", "No decoded text was supplied to a native provider.") };
            var result = await _amsi.ScanStringAsync(text, context.FilePath).WaitAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return new[] { MapResult(context, result) };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        { return new[] { Coverage(context, "AMSI content inspection failed before a complete provider verdict was received.") }; }
        finally { source.Position = original; }
    }

    private static bool IsTextCandidate(FileContentClassification classification) =>
        classification.Formats.Any(f => f is FileContentFormat.Text or FileContentFormat.ScriptCandidate);

    private static SecurityEvidence NotApplicable(DetectionContext context) =>
        Fact(context, "Amsi.NotApplicable", "Observed binary/container structure is not sent to the text-only AMSI detector.");

    private static string DecodeStrict(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe)
            return new UnicodeEncoding(false, true, true).GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff)
            return new UnicodeEncoding(true, true, true).GetString(bytes, 2, bytes.Length - 2);
        int offset = bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf ? 3 : 0;
        return new UTF8Encoding(false, true).GetString(bytes, offset, bytes.Length - offset);
    }

    private SecurityEvidence MapResult(DetectionContext context, AmsiScanResult result)
    {
        bool nativeComplete = result.Source == AmsiVerdictSource.NativeProvider &&
            result.NativeStatus == AmsiNativeScanStatus.Completed && result.NativeHResult == 0 && result.IsComplete;
        SecurityEvidence evidence;
        if (!nativeComplete)
            evidence = Coverage(context, "AMSI did not supply a complete native-provider verdict; local hints are not confirmed malware.");
        else if (result.IsMalicious && result.Result == AmsiDetectionResult.Malicious && result.RawResultCode >= NativeMalwareThreshold)
            evidence = Fact(context, "Amsi.NativeProviderMalware", "Installed native AMSI provider classified the inspected content as malicious.",
                100, EvidenceConfidence.Absolute);
        else if (!result.IsMalicious && result.Result == AmsiDetectionResult.BlockedByAdmin && result.RawResultCode is >= 16384 and <= 20479)
            evidence = Fact(context, "Amsi.AdministrativePolicy", "Installed AMSI provider reported an administrative policy block, not malware certainty.",
                50, EvidenceConfidence.High);
        else if (!result.IsMalicious && ((result.Result == AmsiDetectionResult.Clean && result.RawResultCode == 0) ||
            (result.Result == AmsiDetectionResult.NotDetected && result.RawResultCode is > 0 and < NativeMalwareThreshold &&
             result.RawResultCode is not (>= 16384 and <= 20479))))
            evidence = Fact(context, "Amsi.NativeInspectionCompleted", "Installed AMSI provider completed this text inspection without a malware verdict; other detectors still apply.");
        else
            evidence = Coverage(context, "AMSI result fields did not establish a consistent completed native-provider verdict.");
        evidence.Metadata["VerdictSource"] = result.Source.ToString();
        evidence.Metadata["NativeStatus"] = result.NativeStatus.ToString();
        evidence.Metadata["NativeHResult"] = result.NativeHResult?.ToString(CultureInfo.InvariantCulture) ?? "unavailable";
        evidence.Metadata["NativeResult"] = result.RawResultCode.ToString(CultureInfo.InvariantCulture);
        evidence.Metadata["LocalHints"] = result.HeuristicIndicators.ToString();
        return evidence;
    }

    private static SecurityEvidence Fact(DetectionContext context, string rule, string description,
        int score = 0, EvidenceConfidence confidence = EvidenceConfidence.Low) => new()
    {
        Category = EvidenceCategory.AmsiProvider, SourceDetector = "Detector.AmsiContent",
        CorrelationGroup = "NativeAmsiContent", RuleName = rule, Description = description,
        ScoreContribution = score, Confidence = confidence, FilePath = context.FilePath, SHA256 = context.SHA256,
        ProcessId = context.ProcessId, ParentProcessId = context.ParentProcessId
    };

    private static SecurityEvidence Coverage(DetectionContext context, string reason)
    {
        AddCoverage(context, reason);
        var evidence = Fact(context, "Amsi.IncompleteCoverage", reason);
        evidence.Metadata["Coverage"] = "Incomplete";
        return evidence;
    }

    private static void AddCoverage(DetectionContext context, string reason)
    {
        lock (context.CoverageLimitations)
        {
            if (!context.CoverageLimitations.Contains(reason, StringComparer.Ordinal)) context.CoverageLimitations.Add(reason);
        }
    }
}
