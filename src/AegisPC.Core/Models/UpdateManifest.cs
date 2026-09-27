using System;

namespace AegisPC.Core.Models
{
    public class UpdateManifest
    {
        /// <summary>Product identifier covered by the release signature.</summary>
        public string Product { get; set; } = "UltronDefender";
        /// <summary>Exact signed package length; zero-length packages are rejected.</summary>
        public long PackageSize { get; set; }
        /// <summary>UTC expiry of the signed release metadata.</summary>
        public DateTimeOffset ExpiresUtc { get; set; }
        /// <summary>Base64 RSA-PSS/SHA-256 signature of the canonical signing payload.</summary>
        public string? ManifestSignature { get; set; }
        public required string Version { get; set; }
        public DateTime ReleaseDate { get; set; }
        public required string DownloadUrl { get; set; }
        public required string SHA256 { get; set; }
        public string? ReleaseNotes { get; set; }
        public bool IsRequired { get; set; }
    }
}
