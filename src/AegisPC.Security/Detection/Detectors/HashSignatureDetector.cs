using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Detection.Detectors
{
    public class HashSignatureDetector : IDetectorPlugin
    {
        private readonly IHashService _hashService;
        private readonly IReputationService? _reputationService;
        private readonly AegisPC.Contracts.ThreatIntelligence.IThreatIntelligenceStore _threatStore;

        public string DetectorId => "Detector.HashSignature";
        public string DisplayName => "Zararlı Yazılım İmza ve Hash Dedektörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticSignature;
        public int Priority => 10; // High priority (Fast Path)
        public bool IsEnabled { get; set; } = true;

        public HashSignatureDetector(
            IHashService hashService,
            IReputationService? reputationService = null,
            AegisPC.Contracts.ThreatIntelligence.IThreatIntelligenceStore? threatStore = null)
        {
            _hashService = hashService;
            _reputationService = reputationService;
            _threatStore = threatStore ?? new ThreatIntelligence.ThreatIntelligenceStore();
        }

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            // 1. Compute SHA256 if not provided
            if (string.IsNullOrEmpty(context.SHA256))
            {
                context.SHA256 = await _hashService.ComputeSha256Async(context.FilePath, cancellationToken);
            }

            // 2. Exact Hash Lookup in Threat Intelligence Store
            if (ThreatIntelligence.AuthoritativeThreatCatalog.TryGetOptionalTool(context.SHA256, out var optional) && optional != null)
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticSignature, SourceDetector = DetectorId,
                    RuleName = "SoftwareClassification.OptionalTool", ScoreContribution = 0, Nature = EvidenceNature.SoftwareClassification,
                    Description = "İsteğe bağlı araç sınıflaması: " + optional.ThreatName + "; zararlı kanıtı değildir.",
                    SHA256 = context.SHA256, FilePath = context.FilePath,
                    OptionalToolClassification = new AegisPC.Core.Models.SoftwareClassificationMetadata
                    {
                        SHA256 = optional.Sha256, SourceReference = optional.SourceReference,
                        IntelVersion = optional.PackageVersion, Verified = true, ValidUntilUtc = optional.ValidUntilUtc
                    }
                });
            if (!string.IsNullOrEmpty(context.SHA256))
            {
                if (_threatStore.IsMaliciousHash(context.SHA256, out var record) && record != null && record.IsAuthoritative && record.Category != "PotentiallyUnwantedToolOnly")
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.StaticSignature,
                        SourceDetector = DisplayName,
                        RuleName = $"Signature.Hash.{record.Category}",
                        Description = $"Bilinen Zararlı İmza Eşleşmesi: {record.ThreatName}",
                        ScoreContribution = record.Severity,
                        Confidence = EvidenceConfidence.Absolute,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256,
                        ProcessId = context.ProcessId,
                        ParentProcessId = context.ParentProcessId
                    });
                }
                else if (_threatStore.IsTrustedHash(context.SHA256))
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "Trust.KnownGoodHash",
                        Description = "Doğrulanmış Güvenilir Dosya Özeti (Known Trusted Hash)",
                        ScoreContribution = -100,
                        TrustKind = EvidenceTrustKind.KnownTrustedHash,
                        Confidence = EvidenceConfidence.Absolute,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
                }
                // Local-only edition: no endpoint hash is sent to a reputation provider.
            }

            // 3. Content Pattern & YARA-like Byte Signatures
            var patternMatch = await MalwareSignatureDatabase.CheckFileContentPatternsAsync(context.FilePath, cancellationToken);
            if (patternMatch.IsMatched)
            {
                bool isExactTestSignature =
                    patternMatch.DetectionMethod.Equals("Statik İçerik İmzası", StringComparison.OrdinalIgnoreCase) ||
                    patternMatch.ThreatCategory.Equals("TestMalware", StringComparison.OrdinalIgnoreCase);

                // Generic byte references are not executed scripts, irrespective of extension or publisher.
                // Structured script rules and independently authoritative hashes still run separately.
                if (!isExactTestSignature)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.ScriptHeuristic,
                        SourceDetector = DisplayName,
                        RuleName = $"Documentation.Content.{patternMatch.ThreatCategory}",
                        FeatureIdentity = $"Content.Reference.{patternMatch.ThreatName}",
                        Nature = EvidenceNature.Capability,
                        Description = $"İçerikte metin referansı: {patternMatch.ThreatName}; tek başına saldırı kanıtı değildir.",
                        ScoreContribution = Math.Min(15, patternMatch.SeverityScore),
                        Confidence = EvidenceConfidence.Low,
                        CorrelationGroup = "DocumentationText",
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256,
                        ProcessId = context.ProcessId,
                        ParentProcessId = context.ParentProcessId
                    });
                }
                else
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = isExactTestSignature ? EvidenceCategory.StaticSignature : EvidenceCategory.ScriptHeuristic,
                        SourceDetector = DisplayName,
                        RuleName = $"Signature.Content.{patternMatch.ThreatCategory}",
                        Description = $"İçerik İmzası: {patternMatch.ThreatName}",
                        ScoreContribution = isExactTestSignature ? patternMatch.SeverityScore : Math.Min(65, patternMatch.SeverityScore),
                        Confidence = isExactTestSignature ? EvidenceConfidence.Absolute : EvidenceConfidence.High,
                        CorrelationGroup = isExactTestSignature ? "ExactContentSignature" : "HeuristicCommandText",
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256,
                        ProcessId = context.ProcessId,
                        ParentProcessId = context.ParentProcessId
                    });
                }
            }

            return list;
        }
    }
}
