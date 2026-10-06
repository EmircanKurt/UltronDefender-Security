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
    /// <summary>Collects location review hints and verified signature metadata without exempting development directories or erasing content evidence.</summary>
    public class LocationReputationDetector : IDetectorPlugin
    {
        private readonly ISignatureVerifier _signatureVerifier;

        public string DetectorId => "Detector.LocationReputation";
        public string DisplayName => "Konum, İtibar ve Dijital İmza Analizörü";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.LocationReputation;
        public int Priority => 5; // Fast path
        public bool IsEnabled { get; set; } = true;

        // Bilinen İstenmeyen Program (PUP) ve Hacktool SHA-256 Hash Veritabanı
        private static readonly HashSet<string> KnownPupHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            "E186411FB272847B3E39FCE160B5B110B6343585F84AE8BE98E9B9735F646C0B", // KMSAuto Net
            "02D39620BB9396349F579051833501A74808C78A4BA14C5D76C68564F7986B74", // KMSPico
            "FA01C312DA95D1E168341517454944BA7F27CE2B68DC99F26E650DA90E8F0EF1", // HWIDGen
            "99B2319A56E215BAE99F98822B7853A90DE670498F4F5234D3C579E7802D310C"  // Universal Keygen
        };

        private static readonly HashSet<string> ExecutableAndScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", 
            ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".sys"
        };

        /// <summary>Requires a verifier of the actual file signature; locations and publisher strings alone cannot establish trust.</summary>
        public LocationReputationDetector(ISignatureVerifier signatureVerifier)
        {
            _signatureVerifier = signatureVerifier ?? throw new ArgumentNullException(nameof(signatureVerifier));
        }

        /// <summary>Produces explanatory signature facts and review evidence; verification failures propagate to the hub.</summary>
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
                var sigInfo = context.SharedScan != null
                    ? await context.SharedScan.GetOrVerifySignatureAsync(_signatureVerifier, cancellationToken)
                    : await _signatureVerifier.VerifySignatureAsync(path, cancellationToken);
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
                        ScoreContribution = 0,
                        TrustKind = EvidenceTrustKind.VerifiedAuthenticode,
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
                        FeatureIdentity = "PE.Unsigned",
                        Nature = EvidenceNature.Capability,
                        Description = "Yürütülebilir dosya dijital olarak imzalanmamış",
                        ScoreContribution = 10,
                        Confidence = EvidenceConfidence.Low,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
            }
            catch { throw; }

            // A directory name cannot exempt an executable or script from the same location review rules.
            if (isBinaryOrScript)
            {
                if (PathHelper.IsTempPath(path) || path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.LocationReputation,
                        SourceDetector = DisplayName,
                        RuleName = "Location.TempDirectory",
                        FeatureIdentity = "Location.Temp",
                        Nature = EvidenceNature.Capability,
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
                        FeatureIdentity = "Location.Downloads",
                        Nature = EvidenceNature.Capability,
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
                        FeatureIdentity = "Location.Roaming",
                        Nature = EvidenceNature.Capability,
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
                        FeatureIdentity = "File.ExtensionMismatch",
                        Nature = EvidenceNature.Capability,
                        Description = "Çift uzantı kamuflajı tespit edildi (Örn: .pdf.exe aldatmacası)",
                        ScoreContribution = 75,
                        Confidence = EvidenceConfidence.High,
                        FilePath = path,
                        SHA256 = context.SHA256
                    });
                }
            }

            // 4. PUP / Hacktool Pattern via Known Hashes
            if (isBinaryOrScript && !string.IsNullOrEmpty(context.SHA256) && KnownPupHashes.Contains(context.SHA256))
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.LocationReputation,
                    SourceDetector = DisplayName,
                    RuleName = "Reputation.PUP.KnownHash",
                    Description = "Bilinen İstenmeyen Program / Hacktool imzası (Hash Veritabanı Eşleşmesi)",
                    ScoreContribution = 50,
                    Confidence = EvidenceConfidence.High,
                    FilePath = path,
                    SHA256 = context.SHA256
                });
            }

            // 5. Critical Windows System Binary Masquerading Check (e.g. svchost.exe outside System32)
            var sysBinaryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "services.exe",
                "winlogon.exe", "wininit.exe", "taskhostw.exe", "conhost.exe"
            };
            if (sysBinaryNames.Contains(fileName) && !PathHelper.IsSystemPath(path))
            {
                list.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.AntiEvasion,
                    SourceDetector = DisplayName,
                        RuleName = "Evasion.SystemProcessMasquerading",
                        FeatureIdentity = "File.NameSimilarity",
                        Nature = EvidenceNature.Capability,
                    Description = $"Kritik Windows sistem süreci kamuflajı tespit edildi: '{fileName}' meşru sistem dizini dışında yürütülüyor.",
                    ScoreContribution = 80,
                    Confidence = EvidenceConfidence.High,
                    FilePath = path,
                    SHA256 = context.SHA256
                });
            }

            return list;
        }
    }
}
