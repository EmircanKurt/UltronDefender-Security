using System;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models
{
    /// <summary>
    /// Detailed diagnostic report for an individual file scan operation.
    /// </summary>
    public class FileScanDetailedResult
    {
        public string FilePath { get; set; } = string.Empty;
        public FileScanOutcome Outcome { get; set; } = FileScanOutcome.Success;
        public SecurityFinding? Finding { get; set; }
        public string? ErrorMessage { get; set; }
        public TimeSpan Duration { get; set; } = TimeSpan.Zero;
        public bool IsFromCache { get; set; }
        public bool IsSignedClean { get; set; }
        /// <summary>Explicit configured-inspection coverage, independent of operational outcome; null means the producer did not report it.</summary>
        public bool? InspectionComplete { get; set; }
        /// <summary>Reports observed content independently of the name; null means classification was not performed.</summary>
        public FileContentClassification? ContentClassification { get; set; }
        /// <summary>OS-reported blocking is unavailable Ultron inspection, not a fabricated malware identity.</summary>
        public AegisPC.Core.Exceptions.OperatingSystemFileBlockKind? OperatingSystemBlock { get; set; }

        public static FileScanDetailedResult CreateSuccess(string path, SecurityFinding? finding, TimeSpan duration, bool isFromCache = false, bool isSignedClean = false) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Success, Finding = finding, Duration = duration, IsFromCache = isFromCache, IsSignedClean = isSignedClean };

        public static FileScanDetailedResult CreateSkipped(string path, string reason) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Skipped, ErrorMessage = reason };

        public static FileScanDetailedResult CreateTimeout(string path, TimeSpan duration) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Timeout, Duration = duration, ErrorMessage = "Tarama zaman aşımına uğradı (Per-file timeout)" };

        /// <summary>Records an incomplete file inspection, preserving any finding already proven by inspected bytes.</summary>
        public static FileScanDetailedResult CreateFailed(string path, string error, TimeSpan duration, SecurityFinding? finding = null) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Failed, Duration = duration, ErrorMessage = error, Finding = finding };
    }
}
