namespace AegisPC.Core.Enums;

/// <summary>Distinguishes missing signatures, rejected signatures and unavailable trust checks.</summary>
public enum SignatureVerificationStatus
{
    /// <summary>Verification was not completed or trust could not be established.</summary>
    Unknown,
    /// <summary>No supported embedded or catalog signature was found.</summary>
    Unsigned,
    /// <summary>Windows accepted the file signature under the selected trust policy.</summary>
    Valid,
    /// <summary>Windows rejected the signature or its signer.</summary>
    Invalid
}
