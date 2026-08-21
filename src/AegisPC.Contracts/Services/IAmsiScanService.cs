using System;
using System.Threading.Tasks;
using AegisPC.Core.Enums;

namespace AegisPC.Contracts.Services
{
    public enum AmsiDetectionResult
    {
        Clean = 0,
        NotDetected = 1,
        BlockedByAdmin = 2,
        Malicious = 3,
        Error = 4
    }

    public class AmsiScanResult
    {
        public bool IsMalicious { get; set; }
        public AmsiDetectionResult Result { get; set; }
        public int RawResultCode { get; set; }
        public string ContentName { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public TimeSpan ScanDuration { get; set; }
    }

    public interface IAmsiScanService : IDisposable
    {
        bool IsAmsiSupported { get; }
        Task<AmsiScanResult> ScanStringAsync(string content, string contentName = "DynamicScript");
        Task<AmsiScanResult> ScanBufferAsync(byte[] buffer, string contentName = "MemoryBuffer");
    }
}
