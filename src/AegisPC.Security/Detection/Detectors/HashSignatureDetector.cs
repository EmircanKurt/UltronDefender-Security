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
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
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
                bool isExactTestSignature =
                    patternMatch.DetectionMethod.Equals("Statik İçerik İmzası", StringComparison.OrdinalIgnoreCase) ||
                    patternMatch.ThreatCategory.Equals("TestMalware", StringComparison.OrdinalIgnoreCase);

                string ext = Path.GetExtension(context.FilePath).ToLowerInvariant();
                bool isDocOrText = ext is ".txt" or ".md" or ".doc" or ".docx" or ".pdf" or ".rtf" or ".log" or ".csv" or ".tsv" or ".html" or ".htm" or ".xml" or ".json";

                // Zararsız metin belgelerinde, ders notlarında ve dokümanlarda geçen genel komut sözcükleri (Örn: sekurlsa)
                // çalıştırılamaz içerik olduğu için yüksek puanlı statik imza olarak işaretlenmez.
                if (isDocOrText && !isExactTestSignature)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.ScriptHeuristic,
                        SourceDetector = DisplayName,
                        RuleName = $"Documentation.Content.{patternMatch.ThreatCategory}",
                        Description = $"Metin/Doküman İçi Referans: {patternMatch.ThreatName}",
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
