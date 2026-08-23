namespace AegisPC.Contracts.Archive
{
    public class ArchiveSafetyLimits
    {
        public int MaxNestedDepth { get; set; } = 4;
        public long MaxTotalUncompressedBytes { get; set; } = 500 * 1024 * 1024; // 500 MB max per archive
        public long MaxSingleFileUncompressedBytes { get; set; } = 250 * 1024 * 1024; // 250 MB max per file
        public double MaxCompressionRatio { get; set; } = 100.0; // Ratio > 100:1 -> Zip Bomb
        public int MaxEntryCount { get; set; } = 50000;
    }
}
