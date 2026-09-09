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

        public static FileScanDetailedResult CreateSuccess(string path, SecurityFinding? finding, TimeSpan duration) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Success, Finding = finding, Duration = duration };

        public static FileScanDetailedResult CreateSkipped(string path, string reason) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Skipped, ErrorMessage = reason };

        public static FileScanDetailedResult CreateTimeout(string path, TimeSpan duration) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Timeout, Duration = duration, ErrorMessage = "Tarama zaman aşımına uğradı (Per-file timeout)" };

        public static FileScanDetailedResult CreateFailed(string path, string error, TimeSpan duration) =>
            new() { FilePath = path, Outcome = FileScanOutcome.Failed, Duration = duration, ErrorMessage = error };
    }
}
