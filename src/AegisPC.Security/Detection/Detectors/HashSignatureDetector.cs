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
            if (!string.IsNullOrEmpty(context.SHA256))
            {
                if (_threatStore.IsMaliciousHash(context.SHA256, out var record) && record != null)
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
                        Confidence = EvidenceConfidence.Absolute,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
                }
                else if (_reputationService != null && _reputationService.IsCloudLookupEnabled)
                {
                    // 2b. Bulut Tehdit İstihbaratı ve Gerçek Zamanlı Hash Doğrulama (Abuse.ch MalwareBazaar)
                    try
                    {
                        var cloudResult = await _reputationService.CheckReputationAsync(context.SHA256, cancellationToken);
                        if (cloudResult.IsMalicious)
                        {
                            list.Add(new SecurityEvidence
                            {
                                Category = EvidenceCategory.StaticSignature,
                                SourceDetector = "Bulut Tehdit İstihbarat Motoru (Cloud Reputation)",
                                RuleName = $"Signature.Cloud.{cloudResult.MalwareFamily ?? "Malware"}",
                                Description = $"Bulut İstihbaratı Tehdit Tespiti: {cloudResult.ThreatName ?? "Bilinmeyen Zararlı"}",
                                ScoreContribution = cloudResult.Severity > 0 ? cloudResult.Severity : 100,
                                Confidence = EvidenceConfidence.Absolute,
                                FilePath = context.FilePath,
                                SHA256 = context.SHA256,
                                ProcessId = context.ProcessId,
                                ParentProcessId = context.ParentProcessId
                            });
                        }
                    }
                    catch (Exception)
                    {
                        // Kesintisiz çalışma: Bulut sorgusu başarısız olsa bile yerel analiz devam eder
                    }
                }
            }

            // 3. Content Pattern & YARA-like Byte Signatures
            var patternMatch = await MalwareSignatureDatabase.CheckFileContentPatternsAsync(context.FilePath, cancellationToken);
            if (patternMatch.IsMatched)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticSignature,
                    SourceDetector = DisplayName,
                    RuleName = $"Pattern.{patternMatch.ThreatCategory}",
                    Description = $"İçerik İmzası / Exploit Deseni: {patternMatch.ThreatName}",
                    ScoreContribution = patternMatch.SeverityScore,
                    Confidence = EvidenceConfidence.High,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256,
                    ProcessId = context.ProcessId,
                    ParentProcessId = context.ParentProcessId
                });
            }

            return list;
        }
    }
}
