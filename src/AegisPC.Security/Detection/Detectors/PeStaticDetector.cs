using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Detection.Detectors
{
    public class PeStaticDetector : IDetectorPlugin
    {
        public string DetectorId => "Detector.PeStatic";
        public string DisplayName => "PE Başlık ve İçe Aktarma Statik Analizörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticPeStructure;
        public int Priority => 20;
        public bool IsEnabled { get; set; } = true;

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            // 1. Multi-Signal Suspicious Win32 API Indicators (Only for files outside known safe system/program directories)
            bool isKnownSafe = AegisPC.Core.Helpers.PathHelper.IsKnownSafePath(context.FilePath);
            if (!isKnownSafe)
            {
                var apiIndicators = await MalwareSignatureDatabase.ScanApiIndicatorsAsync(context.FilePath, cancellationToken);
                foreach (var api in apiIndicators)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.StaticApi,
                        SourceDetector = DisplayName,
                        RuleName = $"PE.SuspiciousApi.{api.ApiName}",
                        Description = api.Description,
                        ScoreContribution = api.Weight,
                        Confidence = EvidenceConfidence.Medium,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256,
                        ProcessId = context.ProcessId,
                        ParentProcessId = context.ParentProcessId
                    });
                }
            }

            // 2. Perform PE binary header inspection if PE format
            var peResult = PeAnalyzer.Analyze(context.FilePath);
            if (!peResult.IsPeFile)
            {
                return list;
            }

            // 1. W+X Writable & Executable Section Anomaly
            if (peResult.HasWritableExecutableSection)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DisplayName,
                    RuleName = "PE.Anomaly.WritableExecutableSection",
                    Description = "Hem yazılabilir hem çalıştırılabilir bölüm (W+X anomalisi) — Kod enjeksiyonu veya crypter göstergesi",
                    ScoreContribution = 35,
                    Confidence = EvidenceConfidence.Medium,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }

            // 2. Known Packer Sections (UPX, Themida, MPRESS, etc.)
            if (peResult.IsPacked)
            {
                foreach (var indicator in peResult.PackerIndicators)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.AntiEvasion,
                        SourceDetector = DisplayName,
                        RuleName = "PE.Packer.KnownSignatures",
                        Description = indicator,
                        ScoreContribution = 20,
                        Confidence = EvidenceConfidence.Medium,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
                }
            }

            return list;
        }
    }
}
