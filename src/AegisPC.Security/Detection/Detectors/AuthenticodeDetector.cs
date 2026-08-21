using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;

namespace AegisPC.Security.Detection.Detectors
{
    public class AuthenticodeDetector : IDetectorPlugin
    {
        private readonly ISignatureVerifier _signatureVerifier;

        public string DetectorId => "Detector.Authenticode";
        public string DisplayName => "Authenticode Dijital Sertifika ve Guven Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.DigitalCertificate;
        public int Priority => 8;
        public bool IsEnabled { get; set; } = true;

        public AuthenticodeDetector(ISignatureVerifier signatureVerifier)
        {
            _signatureVerifier = signatureVerifier ?? throw new ArgumentNullException(nameof(signatureVerifier));
        }

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
                var sigInfo = await _signatureVerifier.VerifySignatureAsync(context.FilePath, cancellationToken);
                bool isSystemPath = AegisPC.Core.Helpers.PathHelper.IsSystemPath(context.FilePath);
                bool isKnownSafe = AegisPC.Core.Helpers.PathHelper.IsKnownSafePath(context.FilePath);

                if (sigInfo.IsSigned && sigInfo.IsValid)
                {
                    bool isMs = isSystemPath || (sigInfo.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true);
                    string pub = sigInfo.Publisher ?? (isSystemPath ? "Microsoft Windows" : "Geçerli Yayımcı");

                    if (isMs)
                    {
                        list.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.DigitalCertificate,
                            SourceDetector = DisplayName,
                            RuleName = "Signature.Valid.ValidMicrosoft",
                            Description = $"Geçerli Microsoft Windows Dijital İmzası: {pub}",
                            ScoreContribution = -100, // Full trust discount
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
                            ScoreContribution = -50, // Trust discount
                            Confidence = EvidenceConfidence.High,
                            FilePath = context.FilePath,
                            SHA256 = context.SHA256
                        });
                    }
                }
                else if (isSystemPath)
                {
                    // Legitimate Windows OS binary / component (e.g. WinSxS catalog-verified or OS component)
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "Signature.Valid.ValidMicrosoft",
                        Description = "Korumalı Windows Sistem Bileşeni",
                        ScoreContribution = -100,
                        Confidence = EvidenceConfidence.High,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
                }
                else if (AegisPC.Core.Helpers.GameCrackClassifier.IsGameCrackOrEmulator(context.FilePath))
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "GameCrack.SteamApiWrapper",
                        Description = "Oyun / Steam DRM Emülatör Kütüphanesi (Zararsız Oyun Mod/Crack)",
                        ScoreContribution = 5,
                        Confidence = EvidenceConfidence.Medium,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
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
                else if (!isKnownSafe)
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.DigitalCertificate,
                        SourceDetector = DisplayName,
                        RuleName = "Cert.UnsignedExecutable",
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
            }

            return list;
        }
    }
}
