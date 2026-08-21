using System;

namespace AegisPC.Core.Models
{
    public class DownloadAnalysis
    {
        public required string FilePath { get; set; }
        public string? DownloadUrl { get; set; }
        public string? ReferrerUrl { get; set; }
        public int ZoneId { get; set; }
        public bool IsSigned { get; set; }
        public int ReputationScore { get; set; }
        public required string Verdict { get; set; }
        public DateTime AnalyzedAt { get; set; }
    }
}
