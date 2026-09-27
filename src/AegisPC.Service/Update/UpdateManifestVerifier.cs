using System;
using System.Security.Cryptography;
using System.Text.Json;
using AegisPC.Core.Models;

namespace AegisPC.Service.Update;

/// <summary>Authenticates bounded release metadata using a deployment-pinned public key.</summary>
public sealed class UpdateManifestVerifier
{
    private readonly string? _publicKey;
    private readonly Version _minimumVersion;

    /// <summary>The public key must come from trusted deployment configuration, never the downloaded manifest.</summary>
    public UpdateManifestVerifier(string? publicKeyPem, Version minimumVersion)
    {
        _publicKey = publicKeyPem;
        _minimumVersion = minimumVersion;
    }

    /// <summary>Produces deterministic UTF-8 bytes for release signing; every installation-relevant field is covered.</summary>
    public static byte[] GetSigningPayload(UpdateManifest manifest) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        Schema = 1, manifest.Product, manifest.Version, manifest.DownloadUrl,
        SHA256 = manifest.SHA256.ToUpperInvariant(), manifest.PackageSize,
        ExpiresUnixSeconds = manifest.ExpiresUtc.ToUnixTimeSeconds(),
        ReleaseUtcTicks = manifest.ReleaseDate.ToUniversalTime().Ticks,
        manifest.ReleaseNotes, manifest.IsRequired
    });

    /// <summary>Rejects unauthenticated, expired, oversized or non-upgrade metadata before any filesystem write.</summary>
    public void Verify(UpdateManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (string.IsNullOrWhiteSpace(_publicKey))
            throw new CryptographicException("Updates are disabled until a trusted release public key is configured.");
        if (manifest.Product != "UltronDefender" || !Version.TryParse(manifest.Version, out var version) ||
            version <= _minimumVersion || manifest.Version != version.ToString() ||
            manifest.PackageSize <= 0 || manifest.PackageSize > 512L * 1024 * 1024 ||
            manifest.ExpiresUtc <= DateTimeOffset.UtcNow || manifest.SHA256?.Length != 64 ||
            string.IsNullOrWhiteSpace(manifest.ManifestSignature))
            throw new CryptographicException("Invalid, expired or downgraded release metadata.");
        RequireHttps(manifest.DownloadUrl);
        try
        {
            _ = Convert.FromHexString(manifest.SHA256);
            using var key = RSA.Create();
            key.ImportFromPem(_publicKey);
            if (key.KeySize < 3072 || !key.VerifyData(GetSigningPayload(manifest),
                Convert.FromBase64String(manifest.ManifestSignature), HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw new CryptographicException("Release signature verification failed.");
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new CryptographicException("Malformed release signature or key.", ex);
        }
    }

    /// <summary>Rejects plaintext, relative and credential-bearing update URLs.</summary>
    public static Uri RequireHttps(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo))
            throw new CryptographicException("Updates require an absolute HTTPS URL without credentials.");
        return uri;
    }
}
