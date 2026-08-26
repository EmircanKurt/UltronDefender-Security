using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Helpers;

namespace AegisPC.Security.Detection.Detectors
{
    public class LocationReputationDetector : IDetectorPlugin
    {
        private readonly ISignatureVerifier _signatureVerifier;

        public string DetectorId => "Detector.LocationReputation";
        public string DisplayName => "Konum, İtibar ve Dijital İmza Analizörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.LocationReputation;
        public int Priority => 5; // Fast path
        public bool IsEnabled { get; set; } = true;

        private static readonly HashSet<string> ExactPupKeywords = new(
            new[] { "Y3JhY2s=", "a2V5Z2Vu", "YWN0aXZhdG9y", "cmVwYWNr", "aGFja3Rvb2w=", "dHJhaW5lcg==", "Y2hlYXQ=", "a21zYXV0bw==", "a21zcGljbw==", "aHdpZGdlbg==", "aW5qZWN0b3I=", "c3Bvb2Zlcg==" }
            .Select(b => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b))),
            StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> ExecutableAndScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", 
            ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".sys"
        };

        public LocationReputationDetector(ISignatureVerifier signatureVerifier)
        {
            _signatureVerifier = signatureVerifier;
        }

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            var path = context.FilePath;
            var fileName = context.FileName;
            var ext = Path.GetExtension(fileName).ToLowerInvariant();
            bool isBinaryOrScript = ExecutableAndScriptExtensions.Contains(ext);

            // 1. Digital Signature Check
            bool isSigned = false;
            bool isSignatureValid = false;
            string? publisher = null;

            try
            {
                var sigInfo = await _signatureVerifier.VerifySignatureAsync(path, cancellationToken);
                isSigned = sigInfo.IsSigned;
                isSignatureValid = sigInfo.IsValid;
                publisher = sigInfo.Publisher;

                if (isSigned && isSignatureValid)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "Signature.Valid.TrustedPublisher",
                        Description = $"Doğrulanmış dijital imza: '{publisher ?? "Güvenilir Yayımcı"}'",
                        ScoreContribution = -40, // Trust bonus
                        Confidence = EvidenceConfidence.High,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
                else if (!isSigned && isBinaryOrScript)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "Signature.Unsigned.Binary",
                        Description = "Yürütülebilir dosya dijital olarak imzalanmamış",
                        ScoreContribution = 10,
                        Confidence = EvidenceConfidence.Low,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
            }
            catch { }

            // 2. High-Risk Location Checks (ONLY for binaries/scripts)
            // 2. High-Risk Location Checks (ONLY for binaries/scripts, skip if inside legitimate game/repack or development environment)
            bool isGameDir = PathHelper.IsGameOrRepackDirectory(path);
            bool isDevDir = PathHelper.IsDevelopmentOrPackageDirectory(path);

            if (isBinaryOrScript && !isGameDir && !isDevDir)
            {
                if (PathHelper.IsTempPath(path) || path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.LocationReputation,
                        SourceDetector = DisplayName,
                        RuleName = "Location.TempDirectory",
                        Description = "Dosya geçici dizinde (Temp) çalıştırılıyor veya indirildi",
                        ScoreContribution = 25,
                        Confidence = EvidenceConfidence.Medium,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
                else if (PathHelper.IsUserDownloadsPath(path) && !isSigned)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.LocationReputation,
                        SourceDetector = DisplayName,
                        RuleName = "Location.Downloads.Unsigned",
                        Description = "İmzasız dosya İndirilenler (Downloads) klasöründe bulunuyor",
                        ScoreContribution = 15,
                        Confidence = EvidenceConfidence.Low,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
                else if (path.Contains(@"\AppData\Roaming\", StringComparison.OrdinalIgnoreCase) && !isSigned)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.LocationReputation,
                        SourceDetector = DisplayName,
                        RuleName = "Location.AppDataRoaming.Unsigned",
                        Description = "İmzasız dosya kullanıcı AppData\\Roaming dizininde bulunuyor",
                        ScoreContribution = 15,
                        Confidence = EvidenceConfidence.Low,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
            }

            // 3. Double Extension Disguise (e.g. .pdf.exe, .docx.scr)
            if (fileName.Count(c => c == '.') > 1)
            {
                var lower = fileName.ToLowerInvariant();
                if ((lower.EndsWith(".exe") || lower.EndsWith(".scr") || lower.EndsWith(".vbs") || lower.EndsWith(".bat")) &&
                    (lower.Contains(".pdf.") || lower.Contains(".docx.") || lower.Contains(".xlsx.") || lower.Contains(".jpg.") || lower.Contains(".png.")))
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.AntiEvasion,
                        SourceDetector = DisplayName,
                        RuleName = "Evasion.DoubleExtensionMasking",
                        Description = "Çift uzantı kamuflajı tespit edildi (Örn: .pdf.exe aldatmacası)",
                        ScoreContribution = 75,
                        Confidence = EvidenceConfidence.High,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
            }

            // 4. PUP / Keygen / Crack Pattern (Skipped for recognized game and dev library folders)
            if (!isSigned && isBinaryOrScript && !isGameDir && !isDevDir)
            {
                var fileNameOnly = Path.GetFileNameWithoutExtension(fileName).ToLowerInvariant();
                var tokens = fileNameOnly.Split(new[] { '.', '-', '_', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                bool isPup = tokens.Any(t => ExactPupKeywords.Contains(t)) ||
                             ExactPupKeywords.Any(k => fileNameOnly.Equals(k, StringComparison.OrdinalIgnoreCase));

                if (isPup)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.LocationReputation,
                        SourceDetector = DisplayName,
                        RuleName = "Reputation.PUP.CrackKeygenPattern",
                        Description = "Potansiyel İstenmeyen / Korsan Yazılım (PUP/Crack/Keygen) deseni",
                        ScoreContribution = 50,
                        Confidence = EvidenceConfidence.Medium,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
            }

            return list;
        }
    }
}
