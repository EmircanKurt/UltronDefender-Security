using System.Collections.Generic;
using AegisPC.Contracts.Detection;

namespace AegisPC.Contracts.Archive
{
    public class ArchiveScanVerdict
    {
        public bool IsValidArchive { get; set; }
        public bool HasZipBomb { get; set; }
        public bool IsEncrypted { get; set; }
        public bool IsDepthExceeded { get; set; }
        public bool IsQuotaExceeded { get; set; }
        public int TotalEntryCount { get; set; }
        public long TotalCompressedBytes { get; set; }
        public long TotalUncompressedBytes { get; set; }
        public double HighestCompressionRatio { get; set; }
        public int DeepestLevel { get; set; }
        public List<string> SuspiciousFileNames { get; set; } = new();
        public List<SecurityEvidence> Evidences { get; set; } = new();
        public string Explanation { get; set; } = string.Empty;

        public override string ToString() => $"[ArchiveVerdict: Valid={IsValidArchive}, Bomb={HasZipBomb}, Encrypted={IsEncrypted}, Entries={TotalEntryCount}]";
    }
}
