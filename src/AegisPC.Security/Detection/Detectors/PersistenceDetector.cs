using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Detection.Detectors
{
    public class PersistenceDetector : IDetectorPlugin
    {
        public string DetectorId => "Detector.Persistence";
        public string DisplayName => "Baslangic ve Kalicilik Mekanizmasi Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.Persistence;
        public int Priority => 18;
        public bool IsEnabled { get; set; } = true;

        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath))
            {
                return Task.FromResult<IEnumerable<SecurityEvidence>>(list);
            }

            var path = context.FilePath;

            // 1. Startup folder detection
            if (path.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase) ||
                path.Contains(@"\Startup\", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.Persistence,
                    SourceDetector = DisplayName,
                    RuleName = "Persistence.StartupFolderDrop",
                    Description = "Windows Baslangic Klasorunde Dosya Kaliciligi (Startup Folder Drop)",
                    ScoreContribution = 25,
                    Confidence = EvidenceConfidence.High,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }

            // 2. Registry / Task Persistence indicators in context properties
            if (context.Properties.TryGetValue("PersistenceType", out var pTypeObj) && pTypeObj is string pType)
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.Persistence,
                    SourceDetector = DisplayName,
                    RuleName = $"Persistence.{pType}",
                    Description = $"Sistem Kalicilik Kaydi Tespit Edildi ({pType})",
                    ScoreContribution = 20,
                    Confidence = EvidenceConfidence.Medium,
                    FilePath = context.FilePath,
                    SHA256 = context.SHA256
                });
            }

            return Task.FromResult<IEnumerable<SecurityEvidence>>(list);
        }
    }
}
