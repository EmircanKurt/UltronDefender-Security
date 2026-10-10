using System;

namespace AegisPC.Core.Models;

public class SignatureInfo
{
    /// <summary>Detailed verification outcome; legacy booleans remain for existing consumers.</summary>
    public AegisPC.Core.Enums.SignatureVerificationStatus VerificationStatus { get; set; }
    /// <summary>Native Windows trust result, when a trust check was performed.</summary>
    public int? NativeTrustStatus { get; set; }
    public bool IsSigned { get; set; }
    public bool IsValid { get; set; }
    public string? Publisher { get; set; }
    public string? Issuer { get; set; }
    public string? SerialNumber { get; set; }
    public string? Thumbprint { get; set; }
    public DateTime? ValidFrom { get; set; }
    public DateTime? ValidTo { get; set; }
    public string? SignatureAlgorithm { get; set; }
}
