using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Verifies file integrity and signer trust through Windows Authenticode, without path-based exemptions.</summary>
public class SignatureVerifier : ISignatureVerifier
{
    private readonly ILogger<SignatureVerifier>? _logger;

    /// <summary>Creates a verifier using Windows trust policy and cached revocation information.</summary>
    public SignatureVerifier(ILogger<SignatureVerifier>? logger = null) => _logger = logger;

    /// <summary>Verifies a locked file. Unavailable checks remain unknown, never clean; cancellation propagates.</summary>
    public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new SignatureInfo { VerificationStatus = SignatureVerificationStatus.Unknown };
        try
        {
            // No size/mtime cache: an attacker can preserve both while changing the content.
            using var file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            int status = AuthenticodeTrust.Verify(file, out var certificatePath);
            cancellationToken.ThrowIfCancellationRequested();
            result.NativeTrustStatus = status;
            result.VerificationStatus = status switch
            {
                0 => SignatureVerificationStatus.Valid,
                AuthenticodeTrust.NoSignature => SignatureVerificationStatus.Unsigned,
                unchecked((int)0x80096010) or unchecked((int)0x800B010C) or
                unchecked((int)0x800B0101) or unchecked((int)0x800B0109) or
                unchecked((int)0x800B0111) => SignatureVerificationStatus.Invalid,
                _ => SignatureVerificationStatus.Unknown
            };
            result.IsValid = status == 0;
            result.IsSigned = status == 0;
            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(certificatePath));
                result.IsSigned = true;
                result.Publisher = cert.GetNameInfo(X509NameType.SimpleName, false);
                result.Issuer = cert.GetNameInfo(X509NameType.SimpleName, true);
                result.SerialNumber = cert.SerialNumber;
                result.Thumbprint = cert.Thumbprint;
                result.ValidFrom = cert.NotBefore;
                result.ValidTo = cert.NotAfter;
                result.SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName;
            }
            catch (CryptographicException ex)
            {
                _logger?.LogDebug(ex, "Signer metadata unavailable for {Path}", filePath);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
            CryptographicException or ArgumentException or NotSupportedException)
        {
            _logger?.LogDebug(ex, "Signature verification unavailable for {Path}", filePath);
        }
        return Task.FromResult(result);
    }
}
