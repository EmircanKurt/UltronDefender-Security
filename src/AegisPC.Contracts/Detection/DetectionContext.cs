using System;
using System.Collections.Generic;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Detection
{
    public class ProcessIdentity
    {
        public int ProcessId { get; set; }
        public int ParentProcessId { get; set; }
        public string ImagePath { get; set; } = string.Empty;
        public string ProcessName => System.IO.Path.GetFileName(ImagePath);
        public string CommandLine { get; set; } = string.Empty;
        public string User { get; set; } = string.Empty;
        public string IntegrityLevel { get; set; } = "Medium";
        public string Signer { get; set; } = string.Empty;
        public DateTime? StartTime { get; set; }
    }

    public class FileIdentity
    {
        public string Volume { get; set; } = string.Empty;
        public string FileId { get; set; } = string.Empty;
        public string CanonicalPath { get; set; } = string.Empty;
        public string FileName => System.IO.Path.GetFileName(CanonicalPath);
        public long Size { get; set; }
        public DateTime? CreationTime { get; set; }
        public DateTime? LastWriteTime { get; set; }
        public string SHA256 { get; set; } = string.Empty;
        public string Signer { get; set; } = string.Empty;
    }

    /// <summary>
    /// Tarama yapılacak dosya, süreç veya olay için zenginleştirilmiş bağlam (Context).
    /// </summary>
    public class DetectionContext
    {
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString("N");
        public string FilePath { get; set; } = string.Empty;
        public string FileName => System.IO.Path.GetFileName(FilePath);
        public long FileSize { get; set; }
        public string? SHA256 { get; set; }
        public DateTime? CreationTimeUtc { get; set; }
        public DateTime? LastWriteTimeUtc { get; set; }
        public int? ProcessId { get; set; }
        public int? ParentProcessId { get; set; }
        public string? ProcessName { get; set; }
        public bool IsRunningProcess { get; set; }
        /// <summary>Authenticated caller policy can bypass deep analysis, but cannot suppress authoritative signature inspection.</summary>
        public bool IsUserExcluded { get; set; }
        public FileIdentity? FileIdentity { get; set; }
        public ProcessIdentity? ProcessContext { get; set; }
        public Dictionary<string, object> Properties { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public ScanContext? SharedScan { get; set; }
        /// <summary>Routes all applicable detectors using observed structure; omissions remain explicit coverage.</summary>
        public FileContentClassification? ContentClassification { get; set; }
        public List<string> CoverageLimitations { get; set; } = new();
    }

    /// <summary>
    /// DetectionHub tarafından üretilen birleştirilmiş karar ve kanıt kümesi.
    /// </summary>
    public class DetectionResult
    {
        public string CorrelationId { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string? SHA256 { get; set; }
        public DetectionVerdict Verdict { get; set; } = DetectionVerdict.Unknown;
        /// <summary>True only when the configured analysis finished; a default result is unknown and incomplete.</summary>
        public bool IsComplete { get; set; }
        /// <summary>Explicit user permission, independent of inspection coverage and evidence.</summary>
        public bool PolicyBypassed { get; set; }
        public int FailedDetectorCount { get; set; }
        public List<string> CoverageLimitations { get; set; } = new();
        public DetectionPolicy RecommendedPolicy { get; set; } = DetectionPolicy.Observe;
        public DetectionPolicy Policy { get => RecommendedPolicy; set => RecommendedPolicy = value; }
        public string RecommendedAction => RecommendedPolicy.ToString();
        public int RiskScore { get; set; }
        public int RawScore { get; set; }
        public int DeduplicatedScore { get; set; }
        public int CategoryAdjustedScore { get; set; }
        public double ContextModifier { get; set; } = 1.0;
        public string ScoreTrace { get; set; } = string.Empty;
        public string Severity => RiskScore >= 85 ? "Critical" : (RiskScore >= 70 ? "High" : (RiskScore >= 50 ? "Suspicious" : (RiskScore >= 30 ? "Low" : "Clean")));
        public EvidenceConfidence OverallConfidence { get; set; } = EvidenceConfidence.Low;
        public EvidenceConfidence Confidence { get => OverallConfidence; set => OverallConfidence = value; }
        public string ThreatTitle { get; set; } = string.Empty;
        public List<SecurityEvidence> Evidences { get; set; } = new();
        public FileIdentity? FileIdentity { get; set; }
        public ProcessIdentity? ProcessContext { get; set; }
        public double LatencyMs { get; set; }
        public DateTime ScanTimeUtc { get; set; } = DateTime.UtcNow;
    }
}
