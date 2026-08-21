using System;

namespace AegisPC.ServiceContracts.IpcMessages
{
    public class ScanProgressIpc
    {
        public Guid ScanId { get; set; }
        public required string ScanType { get; set; }
        public double ProgressPercent { get; set; }
        public string? CurrentFile { get; set; }
        public int ScannedFiles { get; set; }
        public int TotalFiles { get; set; }
        public int FindingsCount { get; set; }
        public bool IsCompleted { get; set; }
        public TimeSpan ElapsedTime { get; set; }
    }
}
