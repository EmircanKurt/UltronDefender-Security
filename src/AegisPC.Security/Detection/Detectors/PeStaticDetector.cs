using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Scanning;
using AegisPC.Core.Models;
using System.Linq;

namespace AegisPC.Security.Detection.Detectors
{
    public class PeStaticDetector : IDetectorPlugin
    {
        public string DetectorId => "Detector.PeStatic";
        public string DisplayName => "PE Başlık ve İçe Aktarma Statik Analizörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticPeStructure;
        public int Priority => 20;
        public bool IsEnabled { get; set; } = true;

        /// <summary>Inspects actual PE structures independently of extension; unsupported structural parsing remains explicit.</summary>
        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            var classification = context.ContentClassification ?? context.SharedScan?.ContentClassification;
            if (classification != null && !classification.Formats.Contains(FileContentFormat.PortableExecutable)) return list;
            var peResult = PeAnalyzer.Analyze(context.FilePath);
            if (!peResult.IsPeFile)
            {
                if (classification?.Formats.Contains(FileContentFormat.PortableExecutable) == true)
                    context.CoverageLimitations.Add("PE candidate could not be fully interpreted by the configured static PE parser.");
                return list;
            }

            // API indicators are supporting evidence from PE content, never a directory-based trust exception.
            {
                var apiIndicators = await MalwareSignatureDatabase.ScanApiIndicatorsAsync(context.FilePath, cancellationToken);
                foreach (var api in apiIndicators)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.StaticApi,
                        SourceDetector = DisplayName,
                        RuleName = $"PE.SuspiciousApi.{api.ApiName}",
                        FeatureIdentity = $"PE.Api.{api.ApiName}",
                        Nature = EvidenceNature.Capability,
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

            // 1. W+X Writable & Executable Section Anomaly
            if (peResult.HasWritableExecutableSection)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DisplayName,
                    RuleName = "PE.Anomaly.WritableExecutableSection",
                    FeatureIdentity = "PE.WritableExecutableSection",
                    Nature = EvidenceNature.Capability,
                    Description = "Yazılabilir ve çalıştırılabilir PE bölümü; paketleyici/JIT/mod araçlarında da bulunabilir. Çalıştırılmış saldırı kanıtı değildir.",
                    ScoreContribution = 35,
                    Confidence = EvidenceConfidence.Medium,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }

            // 2. Known Packer Sections (UPX, Themida, VMProtect, .NET Reactor, Enigma, etc.)
            if (peResult.IsPacked)
            {
                string packerName = peResult.PackerName ?? "Bilinmeyen Packer";
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.AntiEvasion,
                    SourceDetector = DisplayName,
                    RuleName = "PE.Packer.ProtectedBinary",
                    FeatureIdentity = "PE.PackingCapability",
                    Nature = EvidenceNature.Capability,
                    Description = $"Paketlenmiş/korunmuş yürütülebilir ({packerName}); tek başına zararlılık kanıtı değildir.",
                    ScoreContribution = 20,
                    Confidence = EvidenceConfidence.Low,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });

                if (!string.IsNullOrEmpty(peResult.TransparencyNote))
                {
                    context.Properties["TransparencyNote"] = peResult.TransparencyNote;
                }
            }

            return list;
        }
    }
}
