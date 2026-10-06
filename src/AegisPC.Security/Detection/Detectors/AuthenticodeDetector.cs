using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;

namespace AegisPC.Security.Detection.Detectors
{
    /// <summary>Records verified Authenticode metadata without granting clean verdicts to locations or subtracting independent positive evidence.</summary>
    public class AuthenticodeDetector : IDetectorPlugin
    {
        private readonly ISignatureVerifier _signatureVerifier;

        public string DetectorId => "Detector.Authenticode";
        public string DisplayName => "Authenticode Dijital Sertifika ve Guven Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.DigitalCertificate;
        public int Priority => 8;
        public bool IsEnabled { get; set; } = true;

        /// <summary>Requires a verifier that validates the signature over the actual file; caller-supplied publisher text is insufficient.</summary>
        public AuthenticodeDetector(ISignatureVerifier signatureVerifier)
        {
            _signatureVerifier = signatureVerifier ?? throw new ArgumentNullException(nameof(signatureVerifier));
        }

        /// <summary>Reports verified signature facts or bounded certificate anomalies; verification failures propagate as incomplete coverage.</summary>
        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();
            if (string.IsNullOrEmpty(context.FilePath) || !File.Exists(context.FilePath))
            {
                return list;
            }

            var ext = Path.GetExtension(context.FilePath).ToLowerInvariant();
            if (ext != ".exe" && ext != ".dll" && ext != ".sys" && ext != ".msi" && ext != ".cat")
            {
                return list;
            }

            try
            {
                var sigInfo = context.SharedScan != null
                    ? await context.SharedScan.GetOrVerifySignatureAsync(_signatureVerifier, cancellationToken)
                    : await _signatureVerifier.VerifySignatureAsync(context.FilePath, cancellationToken);
                if (sigInfo.IsSigned && sigInfo.IsValid)
                {
                    bool isMs = AegisPC.Security.Safety.TrustedSoftwarePolicy.IsTrustedOsPublisher(sigInfo.Publisher);
                    string pub = sigInfo.Publisher ?? "Geçerli Yayımcı";

                    if (isMs)
                    {
                        list.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.DigitalCertificate,
                            SourceDetector = DisplayName,
                            RuleName = "Signature.Valid.ValidMicrosoft",
                            Description = $"Geçerli Microsoft Windows Dijital İmzası: {pub}",
                            ScoreContribution = 0,
                            TrustKind = EvidenceTrustKind.VerifiedOsAuthenticode,
                            Confidence = EvidenceConfidence.Absolute,
                            FilePath = context.FilePath,
                            SHA256 = context.SHA256
                        });
                    }
                    else
                    {
                        list.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.DigitalCertificate,
                            SourceDetector = DisplayName,
                            RuleName = "Signature.Valid.TrustedPublisher",
                            Description = $"Geçerli Güvenilir Üretici Sertifikası: {pub}",
                            ScoreContribution = 0,
                            TrustKind = EvidenceTrustKind.VerifiedAuthenticode,
                            Confidence = EvidenceConfidence.High,
                            FilePath = context.FilePath,
                            SHA256 = context.SHA256
                        });
                    }
                }
                else if (sigInfo.IsSigned && !sigInfo.IsValid)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "Cert.InvalidSignature",
                        Description = "Bozuk, Geçersiz veya Tahrif Edilmiş Dijital İmza",
                        ScoreContribution = 40,
                        Confidence = EvidenceConfidence.High,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
                }
                else
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "Cert.UnsignedExecutable",
                        FeatureIdentity = "PE.Unsigned",
                        Nature = EvidenceNature.Capability,
                        Description = "İmzasız Çalıştırılabilir Dosya (Unsigned Binary)",
                        ScoreContribution = 10,
                        Confidence = EvidenceConfidence.Low,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
                }
            }
            catch
            {
                throw; // Let the hub report incomplete coverage; failure is not a clean signature.
            }

            return list;
        }
    }
}
