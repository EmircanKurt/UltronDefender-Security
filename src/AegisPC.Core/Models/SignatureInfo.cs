using System;

namespace AegisPC.Core.Models;

public class SignatureInfo
{
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
