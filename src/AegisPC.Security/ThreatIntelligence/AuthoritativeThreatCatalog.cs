using System;
using AegisPC.Contracts.ThreatIntelligence;

namespace AegisPC.Security.ThreatIntelligence;

/// <summary>
/// Common manual/real-time source of exact verified hashes. Unsigned SQLite/XOR imports cannot
/// enter this catalogue. Deployment packages remain disabled until a publisher key is provisioned.
/// </summary>
public static class AuthoritativeThreatCatalog
{
    // No demo/private key or settings-supplied trust anchor. Provision via a reviewed signed build.
    internal const string PublisherPublicKeyPem = "";
    internal static readonly SignedThreatIntelStore Packages = new(PublisherPublicKeyPem);
    /// <summary>Usable exact records, including two separately labeled built-in test hashes.</summary>
    public static int Count => 2 + Packages.Count;

    /// <summary>Returns detached verified evidence; an absent/invalid hash provides no clean-content proof.</summary>
    public static bool TryGet(string? sha256, out ThreatIntelRecord? record)
    {
        record = null;
        if (!Sha256Identity.IsValid(sha256)) return false;
        string hash = sha256!.ToUpperInvariant();
        string? name = hash switch
        {
            "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F" => "EICAR-Standard-AV-Test-File",
            "131F95C51CC819465FA1797F6CCACF9D494AAAFF46FA3EAC73AE63FFBCF18291" => "EICAR-Standard-AV-Test-CRLF",
            _ => null
        };
        if (name == null)
        {
            if (!Packages.TryGet(hash, out record)) return false;
            if (record?.Category != "PotentiallyUnwantedToolOnly") return true;
            record = null; return false; // Optional tools are not malware hashes.
        }
        record = new ThreatIntelRecord
        {
            Sha256 = hash, ThreatName = name, Category = "TestMalware", Source = "EICAR",
            SourceReference = "https://www.eicar.org/download-anti-malware-testfile/",
            PackageVersion = "built-in-test-v1", Verification = ThreatIntelVerification.BuiltInTestMarker,
            TimestampUtc = DateTime.UnixEpoch
        };
        return true;
    }

    /// <summary>Only a current authenticated explicit tool-only classification is optional, never arbitrary HackTool labels.</summary>
    public static bool TryGetOptionalTool(string? sha256, out ThreatIntelRecord? record)
    {
        record = null;
        if (sha256 == null || !Packages.TryGet(sha256, out var verified) || verified?.Category != "PotentiallyUnwantedToolOnly") return false;
        record = verified; return true;
    }

    /// <summary>Stable intel identity for cache invalidation; visibility preferences are intentionally excluded.</summary>
    public static string CacheIdentity => $"built-in-test-v1:{Packages.HighestSequence}:{Packages.Count}";
}
