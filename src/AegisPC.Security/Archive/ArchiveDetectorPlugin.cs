using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Archive;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Archive;

/// <summary>
/// Routes ZIP-family/JAR member inspection into the same DetectionHub used by normal and real-time scans.
/// Unsupported or incomplete member coverage remains explicit; generic rule matches are not confirmed malware.
/// </summary>
public class ArchiveDetectorPlugin : IDetectorPlugin
{
    private readonly ISecureArchiveEngine? _legacyArchiveEngine;
    private readonly ArchiveSafetyScanner? _memberScanner;

    /// <summary>Identifies this archive evidence provider independently of member filenames.</summary>
    public string DetectorId => "SecureArchiveDetector";
    /// <summary>Returns the user-facing detector label for ZIP-family content inspection.</summary>
    public string DisplayName => "Bounded Archive Member Detector";
    /// <summary>Declares structural archive anomalies as the primary category; exact member signatures retain their own category.</summary>
    public EvidenceCategory PrimaryCategory => EvidenceCategory.ArchiveAnomaly;
    /// <summary>Places archive member inspection after primary static identity detectors.</summary>
    public int Priority => 25;
    /// <summary>Allows trusted application configuration to enable this provider.</summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Accepts a shared bounded member scanner. Explicit legacy-engine callers retain their prior inspection API.
    /// The default member scanner has hash/pattern inspection; the factory supplies the configured shared YARA engine.
    /// </summary>
    public ArchiveDetectorPlugin(ISecureArchiveEngine? archiveEngine = null, ArchiveSafetyScanner? memberScanner = null)
    {
        _legacyArchiveEngine = archiveEngine != null && memberScanner == null ? archiveEngine : null;
        _memberScanner = memberScanner ?? (archiveEngine == null ? new ArchiveSafetyScanner() : null);
    }

    /// <summary>
    /// Emits outer-container evidence with decompressed member hashes in metadata, never synthetic quarantine paths.
    /// Reuses an actual per-file archive result supplied by the scanner instead of decompressing it a second time.
    /// </summary>
    public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(context.FilePath) || !File.Exists(context.FilePath)) return Array.Empty<SecurityEvidence>();
        if (_legacyArchiveEngine != null) return await EvaluateLegacyAsync(context, cancellationToken);

        ArchiveScanResult inspected;
        if (context.Properties.TryGetValue("Ultron.ArchiveInspectionResult", out var previous) && previous is ArchiveScanResult result)
            inspected = result;
        else
        {
            var classification = context.ContentClassification ?? context.SharedScan?.ContentClassification;
            if (classification == null)
            {
                using var source = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                classification = await new FileContentClassifier().ClassifyAsync(source, Path.GetExtension(context.FilePath), cancellationToken);
                context.ContentClassification = classification;
                if (context.SharedScan != null) context.SharedScan.ContentClassification = classification;
                context.CoverageLimitations.AddRange(classification.CoverageLimitations);
            }
            if (!classification.RequiresZipInspection)
            {
                if (classification.Formats.Contains(FileContentFormat.UnsupportedContainer))
                    context.CoverageLimitations.Add("Archive member content is unsupported by the configured unpacker.");
                return Array.Empty<SecurityEvidence>();
            }
            inspected = await _memberScanner!.ScanArchiveAsync(context.FilePath, cancellationToken, contentIdentifiedZip: true);
        }

        if (!inspected.IsComplete)
            context.CoverageLimitations.Add(inspected.CoverageLimitation ?? "Archive member inspection did not complete.");

        var evidences = new List<SecurityEvidence>();
        foreach (var finding in inspected.Findings)
        {
            bool exact = finding.Category == FindingCategory.KnownMalwareHash && finding.RiskLevel == RiskLevel.ConfirmedMalicious;
            var evidence = new SecurityEvidence
            {
                SourceDetector = DetectorId,
                RuleName = exact ? "Archive.Member.ExactSignature" : $"Archive.Member.{finding.Category}",
                Category = exact || finding.Category == FindingCategory.MalwareSuspicion ? EvidenceCategory.StaticSignature
                    : finding.Category == FindingCategory.SuspiciousScript ? EvidenceCategory.ScriptHeuristic : EvidenceCategory.ArchiveAnomaly,
                Confidence = exact ? EvidenceConfidence.Absolute : EvidenceConfidence.High,
                ScoreContribution = exact ? finding.RiskScore : Math.Min(75, finding.RiskScore),
                CorrelationGroup = "ArchiveMember:" + (finding.SHA256 ?? finding.ObjectPath),
                Description = finding.Title + " — " + finding.Description,
                FilePath = context.FilePath,
                SHA256 = context.SHA256,
                ProcessId = context.ProcessId,
                ParentProcessId = context.ParentProcessId
            };
            string marker = context.FilePath + " -> ";
            evidence.Metadata["ArchiveMember"] = finding.ObjectPath.StartsWith(marker, StringComparison.Ordinal)
                ? finding.ObjectPath[marker.Length..] : finding.ObjectName;
            evidence.Metadata["ArchiveMemberSHA256"] = finding.SHA256 ?? string.Empty;
            // Retain distinct member identities when the hub deduplicates evidence on the outer path.
            evidence.FeatureIdentity = $"ArchiveMember:{evidence.Metadata["ArchiveMember"]}:{finding.SHA256}:{evidence.RuleName}";
            evidences.Add(evidence);
        }
        return evidences;
    }

    private async Task<IEnumerable<SecurityEvidence>> EvaluateLegacyAsync(DetectionContext context, CancellationToken cancellationToken)
    {
        string ext = Path.GetExtension(context.FilePath).ToLowerInvariant();
        if (ext is not ".zip" and not ".iso") return Array.Empty<SecurityEvidence>();
        var verdict = await _legacyArchiveEngine!.InspectArchiveAsync(context.FilePath, null, cancellationToken);
        if (!verdict.IsValidArchive || verdict.IsQuotaExceeded || verdict.IsDepthExceeded)
            context.CoverageLimitations.Add(verdict.Explanation ?? "Legacy archive inspection did not complete.");
        foreach (var evidence in verdict.Evidences)
        {
            evidence.SourceDetector = DetectorId;
            evidence.FilePath = context.FilePath;
        }
        return verdict.Evidences;
    }

}
