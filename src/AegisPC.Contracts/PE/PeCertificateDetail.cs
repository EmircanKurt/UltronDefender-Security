using System;
using System.Collections.Generic;

namespace AegisPC.Contracts.PE
{
    /// <summary>
    /// Authenticode dijital imza ve X509 sertifika zinciri derin doğrulama bilgisi.
    /// </summary>
    public class PeCertificateDetail
    {
        public bool IsSigned { get; set; }
        public bool IsValid { get; set; }
        public string Subject { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Thumbprint { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public DateTime? ValidFrom { get; set; }
        public DateTime? ValidTo { get; set; }
        public string SignatureAlgorithm { get; set; } = string.Empty;

        /// <summary>
        /// Sertifika kendine mi ait (Self-Signed)
        /// </summary>
        public bool IsSelfSigned { get; set; }

        /// <summary>
        /// Sertifikanın geçerlilik süresi dolmuş mu
        /// </summary>
        public bool IsExpired { get; set; }

        /// <summary>
        /// Microsoft Windows veya Doğrulanmış Windows Kök Otoritesi tarafından mı imzalanmış
        /// </summary>
        public bool IsMicrosoftTrusted { get; set; }

        /// <summary>
        /// Zaman damgası sertifikası (Timestamp Counter-Signature) var mı
        /// </summary>
        public bool HasTimestampCounterSignature { get; set; }

        /// <summary>
        /// X509 Zincir Hataları (UntrustedRoot, PartialChain, Revoked vb.)
        /// </summary>
        public List<string> ChainErrors { get; set; } = new();

        public override string ToString() => $"Certificate: Signed={IsSigned}, Valid={IsValid}, Subject='{Subject}', Microsoft={IsMicrosoftTrusted}";
    }
}
