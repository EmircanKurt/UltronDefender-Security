using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.PE;

namespace AegisPC.Security.PE
{
    /// <summary>
    /// Taşınabilir Yürütülebilir (PE) dosyaların derin başlık, Rich Header, TLS Callback,
    /// Bölüm Anomalileri (W+X) ve Authenticode sertifikalarını inceleyerek DetectionHub için Kanıt (SecurityEvidence) üreten eklenti.
    /// </summary>
    public class DeepPeDetector : IDetectorPlugin
    {
        private readonly IDeepPeAnalyzer _peAnalyzer;

        public string DetectorId => "DeepPeDetector";
        public string DisplayName => "Deep PE Header & Certificate Detector";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticPeStructure;
        public int Priority => 30; // Hash (10) ve Pattern (20) dedektörlerinden sonra çalışır
        public bool IsEnabled { get; set; } = true;

        public DeepPeDetector(IDeepPeAnalyzer? peAnalyzer = null)
        {
            _peAnalyzer = peAnalyzer ?? new DeepPeAnalyzer();
        }

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var evidences = new List<SecurityEvidence>();

            if (string.IsNullOrWhiteSpace(context.FilePath) || !File.Exists(context.FilePath))
            {
                return evidences;
            }

            var peResult = await _peAnalyzer.AnalyzeAsync(context.FilePath, cancellationToken);
            if (!peResult.IsPeFile)
            {
                return evidences;
            }

            // 1. TLS Callbacks (Gizli / Erken Kod Yürütme)
            if (peResult.HasTlsCallbacks)
            {
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DetectorId,
                    RuleName = "PE_TLS_CALLBACK_DETECTED",
                    ScoreContribution = 20,
                    Confidence = EvidenceConfidence.High,
                    Description = $"PE dosyasında TLS Callback/Directory bulundu (main() öncesi erken yürütme / Anti-Debug).",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["TlsCount"] = peResult.TlsCallbackCount.ToString(),
                        ["ExecutableType"] = peResult.ExecutableType
                    }
                });
            }

            // 2. W+X Anomalisi (Hem Yazılabilir Hem Çalıştırılabilir Bölüm)
            if (peResult.HasWritableExecutableSection)
            {
                var wxSections = peResult.Sections.Where(s => s.IsWritableAndExecutable).Select(s => s.Name).ToList();
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DetectorId,
                    RuleName = "PE_WX_SECTION_DETECTED",
                    ScoreContribution = 35,
                    Confidence = EvidenceConfidence.Absolute,
                    Description = $"PE dosyasında hem yazılabilir hem çalıştırılabilir bölüm bulundu: '{string.Join(", ", wxSections)}' (Self-modifying code / Unpacker).",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["WxSections"] = string.Join(";", wxSections)
                    }
                });
            }

            // 3. Bilinen Packer Bölüm İsimleri (UPX, Themida, VMProtect, Aspack)
            if (peResult.PackerIndicators.Count > 0)
            {
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DetectorId,
                    RuleName = "PE_KNOWN_PACKER_SECTION",
                    ScoreContribution = 30,
                    Confidence = EvidenceConfidence.High,
                    Description = $"PE dosyasında bilinen packer/koruyucu imzası bulundu: {string.Join(" ", peResult.PackerIndicators)}",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["PackerIndicators"] = string.Join(";", peResult.PackerIndicators)
                    }
                });
            }

            // 4. Yüksek Bölüm Entropisi (> 7.2)
            if (peResult.HasHighEntropySections)
            {
                var highEntSections = peResult.Sections.Where(s => s.Entropy >= 7.2).Select(s => $"{s.Name} ({s.Entropy:F2}/8.0)").ToList();
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.EntropyAnomaly,
                    SourceDetector = DetectorId,
                    RuleName = "PE_HIGH_ENTROPY_PACKED_SECTION",
                    ScoreContribution = 25,
                    Confidence = EvidenceConfidence.High,
                    Description = $"PE bölümlerinde şüpheli yüksek Shannon entropisi tespit edildi: {string.Join(", ", highEntSections)}",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["MaxEntropy"] = peResult.MaxSectionEntropy.ToString("F2")
                    }
                });
            }

            // 5. Şüpheli İçe Aktarılan API'lar (Process Injection / Hooking)
            if (peResult.SuspiciousImportedApis.Count >= 2)
            {
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticApi,
                    SourceDetector = DetectorId,
                    RuleName = "PE_SUSPICIOUS_IMPORTS_DETECTED",
                    ScoreContribution = 25,
                    Confidence = EvidenceConfidence.High,
                    Description = $"PE dosyasının içe aktarım tablosunda tehlikeli Win32 API'ları bulundu: {string.Join(", ", peResult.SuspiciousImportedApis)}",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Apis"] = string.Join(";", peResult.SuspiciousImportedApis)
                    }
                });
            }

            // 6. Authenticode Sertifika Durumu
            if (peResult.Certificate.IsSigned)
            {
                if (peResult.Certificate.IsValid && peResult.Certificate.IsMicrosoftTrusted)
                {
                    // Güven Kredisi (-50 Negatif Skor)
                    evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DetectorId,
                        RuleName = "CERT_TRUSTED_MICROSOFT_CA",
                        ScoreContribution = -50,
                        Confidence = EvidenceConfidence.Absolute,
                        Description = $"Dosya geçerli Microsoft Windows dijital sertifikasına veya Windows Kataloğuna sahiptir ({peResult.Certificate.Subject}).",
                        FilePath = context.FilePath,
                        Metadata = new Dictionary<string, string>
                        {
                            ["Publisher"] = peResult.Certificate.Subject,
                            ["Issuer"] = peResult.Certificate.Issuer
                        }
                    });
                }
                else if (peResult.Certificate.IsExpired)
                {
                    evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DetectorId,
                        RuleName = "CERT_EXPIRED",
                        ScoreContribution = 20,
                        Confidence = EvidenceConfidence.High,
                        Description = $"Dosyanın dijital sertifikasının geçerlilik süresi dolmuştur ({peResult.Certificate.ValidTo:yyyy-MM-dd}).",
                        FilePath = context.FilePath,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ValidTo"] = peResult.Certificate.ValidTo?.ToString("O") ?? string.Empty
                        }
                    });
                }
                else if (peResult.Certificate.IsSelfSigned)
                {
                    evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DetectorId,
                        RuleName = "CERT_SELF_SIGNED_UNTRUSTED",
                        ScoreContribution = 15,
                        Confidence = EvidenceConfidence.Medium,
                        Description = $"Dosya güvenilmeyen veya kendi kendine imzalanmış bir sertifika taşımaktadır ({peResult.Certificate.Subject}).",
                        FilePath = context.FilePath,
                        Metadata = new Dictionary<string, string>
                        {
                            ["Subject"] = peResult.Certificate.Subject
                        }
                    });
                }
                else if (!peResult.Certificate.IsValid && !AegisPC.Core.Helpers.GameCrackClassifier.IsGameCrackOrEmulator(context.FilePath))
                {
                    evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DetectorId,
                        RuleName = "CERT_INVALID_OR_REVOKED",
                        ScoreContribution = 45,
                        Confidence = EvidenceConfidence.Absolute,
                        Description = $"Dosyanın dijital imza zinciri doğrulanamadı: {string.Join("; ", peResult.Certificate.ChainErrors)}",
                        FilePath = context.FilePath,
                        Metadata = new Dictionary<string, string>
                        {
                            ["Errors"] = string.Join(";", peResult.Certificate.ChainErrors)
                        }
                    });
                }
            }

            return evidences;
        }
    }
}
