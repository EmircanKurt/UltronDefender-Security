using System;

namespace AegisPC.Core.Models
{
    public class UpdateManifest
    {
        public required string Version { get; set; }
        public DateTime ReleaseDate { get; set; }
        public required string DownloadUrl { get; set; }
        public required string SHA256 { get; set; }
        public string? ReleaseNotes { get; set; }
        public bool IsRequired { get; set; }
    }
}
