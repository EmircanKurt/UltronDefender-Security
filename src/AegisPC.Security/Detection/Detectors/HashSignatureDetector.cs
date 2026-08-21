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

        public string DetectorId => "Detector.HashSignature";
        public string DisplayName => "Zararlı Yazılım İmza ve Hash Dedektörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticSignature;
        public int Priority => 10; // High priority (Fast Path)
        public bool IsEnabled { get; set; } = true;

        public HashSignatureDetector(IHashService hashService)
        {
            _hashService = hashService;
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

            // 2. Exact Hash Lookup in Signature Database
            if (!string.IsNullOrEmpty(context.SHA256))
            {
                var hashMatch = MalwareSignatureDatabase.CheckHash(context.SHA256);
                if (hashMatch.IsMatched)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.StaticSignature,
                        SourceDetector = DisplayName,
                        RuleName = $"Signature.Hash.{hashMatch.ThreatCategory}",
                        Description = $"Bilinen Zararlı İmza Eşleşmesi: {hashMatch.ThreatName}",
                        ScoreContribution = hashMatch.SeverityScore,
                        Confidence = EvidenceConfidence.Absolute,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256,
                        ProcessId = context.ProcessId,
                        ParentProcessId = context.ParentProcessId
                    });
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
