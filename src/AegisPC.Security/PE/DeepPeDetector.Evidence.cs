using System.Collections.Generic;
using System.Linq;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.PE;

namespace AegisPC.Security.PE;

public partial class DeepPeDetector
{
    private void AddTlsEvidence(PeDeepAnalysisResult peResult, DetectionContext context, List<SecurityEvidence> evidences)
    {

            if (!peResult.IsTlsInspectionComplete)
                context.CoverageLimitations.Add("TlsStructureInspectionIncomplete");
            if (peResult.HasTlsCallbacks)
            {
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DetectorId,
                    RuleName = "PE_TLS_CALLBACK_DETECTED",
                    FeatureIdentity = "PE.TlsCallbacks",
                    Nature = EvidenceNature.Capability,
                    ScoreContribution = 0,
                    Confidence = EvidenceConfidence.High,
                    Description = "Doğrulanmış TLS callback tablosu bulundu; bu normal Windows yürütülebilirlerinde de kullanılabilir.",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["TlsCount"] = peResult.TlsCallbackCount.ToString(),
                        ["ExecutableType"] = peResult.ExecutableType
                    }
                });
            }
    }

    private void AddWritableExecutableEvidence(PeDeepAnalysisResult peResult, DetectionContext context, List<SecurityEvidence> evidences)
    {

            if (peResult.HasWritableExecutableSection)
            {
                var wxSections = peResult.Sections.Where(s => s.IsWritableAndExecutable).Select(s => s.Name).ToList();
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DetectorId,
                    RuleName = "PE_WX_SECTION_DETECTED",
                    FeatureIdentity = "PE.WritableExecutableSection",
                    Nature = EvidenceNature.Capability,
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
    }

    private void AddPackingEvidence(PeDeepAnalysisResult peResult, DetectionContext context, List<SecurityEvidence> evidences)
    {

            if (peResult.PackerIndicators.Count > 0)
            {
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticPeStructure,
                    SourceDetector = DetectorId,
                    RuleName = "PE_KNOWN_PACKER_SECTION",
                    FeatureIdentity = "PE.PackingCapability",
                    Nature = EvidenceNature.Capability,
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
    }

    private void AddEntropyEvidence(PeDeepAnalysisResult peResult, DetectionContext context, List<SecurityEvidence> evidences)
    {

            if (peResult.HasHighEntropySections)
            {
                var highEntSections = peResult.Sections.Where(s => s.Entropy >= 7.2).Select(s => $"{s.Name} ({s.Entropy:F2}/8.0)").ToList();
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.EntropyAnomaly,
                    SourceDetector = DetectorId,
                    RuleName = "PE_HIGH_ENTROPY_PACKED_SECTION",
                    FeatureIdentity = "PE.Entropy",
                    Nature = EvidenceNature.Capability,
                    ScoreContribution = 25,
                    Confidence = EvidenceConfidence.High,
                    Description = $"PE bölümlerinde yüksek Shannon entropisi ölçüldü: {string.Join(", ", highEntSections)}; tek başına zararlılık kanıtı değildir.",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["MaxEntropy"] = peResult.MaxSectionEntropy.ToString("F2")
                    }
                });
            }
    }

    private void AddImportedApiEvidence(PeDeepAnalysisResult peResult, DetectionContext context, List<SecurityEvidence> evidences)
    {

            if (peResult.SuspiciousImportedApis.Count >= 2)
            {
                evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.StaticApi,
                    SourceDetector = DetectorId,
                    RuleName = "PE_SUSPICIOUS_IMPORTS_DETECTED",
                    FeatureIdentity = "PE.ImportedApiCapabilities",
                    Nature = EvidenceNature.Capability,
                    ScoreContribution = 25,
                    Confidence = EvidenceConfidence.High,
                    Description = $"PE içe aktarım tablosundaki API yetenekleri: {string.Join(", ", peResult.SuspiciousImportedApis)}; çağrı veya çalıştırılmış saldırı kanıtı değildir.",
                    FilePath = context.FilePath,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Apis"] = string.Join(";", peResult.SuspiciousImportedApis)
                    }
                });
            }
    }

    private void AddCertificateEvidence(PeDeepAnalysisResult peResult, DetectionContext context, List<SecurityEvidence> evidences)
    {

            if (peResult.Certificate.VerificationStatus == AegisPC.Core.Enums.SignatureVerificationStatus.Unknown)
                context.CoverageLimitations.Add("SignatureVerificationUnavailable");
            if (peResult.Certificate.IsSigned && peResult.Certificate.VerificationStatus != AegisPC.Core.Enums.SignatureVerificationStatus.Unknown)
            {
                if (peResult.Certificate.IsValid && peResult.Certificate.IsMicrosoftTrusted)
                {
                    evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DetectorId,
                        RuleName = "CERT_TRUSTED_MICROSOFT_CA",
                        ScoreContribution = 0,
                        TrustKind = EvidenceTrustKind.VerifiedOsAuthenticode,
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
                else if (peResult.Certificate.VerificationStatus != AegisPC.Core.Enums.SignatureVerificationStatus.Valid && peResult.Certificate.IsExpired)
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
                else if (peResult.Certificate.VerificationStatus != AegisPC.Core.Enums.SignatureVerificationStatus.Valid && peResult.Certificate.IsSelfSigned)
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
                else if (peResult.Certificate.VerificationStatus == AegisPC.Core.Enums.SignatureVerificationStatus.Invalid)
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
    }

}
