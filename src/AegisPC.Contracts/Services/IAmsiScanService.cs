using System;
using System.Threading.Tasks;
using AegisPC.Core.Enums;

namespace AegisPC.Contracts.Services
{
    /// <summary>Distinguishes native provider verdicts from unconfirmed local review hints and unavailable coverage.</summary>
    public enum AmsiDetectionResult
    {
        Clean = 0,
        NotDetected = 1,
        BlockedByAdmin = 2,
        Malicious = 3,
        Error = 4,
        /// <summary>A local heuristic found review hints without establishing malware certainty.</summary>
        Suspicious = 5,
        /// <summary>The native provider did not complete; absence of local hints cannot establish cleanliness.</summary>
        Unknown = 6
    }

    /// <summary>Identifies who supplied the reported verdict; local heuristics never impersonate a native AMSI result.</summary>
    public enum AmsiVerdictSource
    {
        /// <summary>No content was supplied and no provider scan was performed.</summary>
        EmptyInput,
        /// <summary>An installed AMSI provider completed the native request.</summary>
        NativeProvider,
        /// <summary>Only local, bounded heuristic inspection completed.</summary>
        HeuristicFallback,
        /// <summary>The complete content matched the canonical antivirus test file, independently of native AMSI.</summary>
        CanonicalTestSignature
    }

    /// <summary>Records native request coverage separately from local heuristic observations.</summary>
    public enum AmsiNativeScanStatus
    {
        /// <summary>No native request was needed for empty input.</summary>
        NotAttempted,
        /// <summary>The native library or initialized context was unavailable.</summary>
        Unavailable,
        /// <summary>The native request completed with a valid AMSI_RESULT.</summary>
        Completed,
        /// <summary>The native request returned an error or failed before a valid result was received.</summary>
        Failed
    }

    /// <summary>Local review hints are informational and cannot authorize quarantine, process termination, or a confirmed verdict.</summary>
    [Flags]
    public enum AmsiHeuristicIndicators
    {
        /// <summary>No supported local review hint was found in the inspected bytes.</summary>
        None = 0,
        /// <summary>Text referenced AMSI bypass techniques; this may also be legitimate documentation.</summary>
        DefenseEvasionReference = 1,
        /// <summary>Text referenced download-and-execute command composition.</summary>
        DownloadExecutionReference = 2,
        /// <summary>Text referenced recovery configuration removal or disabling.</summary>
        RecoveryTamperingReference = 4
    }

    /// <summary>Reports native coverage, provider verdict, and separate heuristic review metadata without fabricating provider success.</summary>
    public class AmsiScanResult
    {
        /// <summary>True only for a successful native malware verdict or independently verified complete canonical test content.</summary>
        public bool IsMalicious { get; set; }
        /// <summary>Contains the provider verdict or explicit unknown/suspicious fallback classification.</summary>
        public AmsiDetectionResult Result { get; set; }
        /// <summary>Contains AMSI_RESULT only when NativeStatus is Completed; fallback never invents the malware result code.</summary>
        public int RawResultCode { get; set; }
        /// <summary>Identifies the source of the verdict independently of its description text.</summary>
        public AmsiVerdictSource Source { get; set; }
        /// <summary>Records whether a native provider completed the request or coverage was unavailable/failed.</summary>
        public AmsiNativeScanStatus NativeStatus { get; set; }
        /// <summary>Preserves the native HRESULT when one was received; null means no native status code was obtained.</summary>
        public int? NativeHResult { get; set; }
        /// <summary>True only when the entire supplied content was inspected by the native provider or no content was supplied.</summary>
        public bool IsComplete { get; set; }
        /// <summary>Contains unconfirmed local review hints separately from the native result.</summary>
        public AmsiHeuristicIndicators HeuristicIndicators { get; set; }
        /// <summary>Identifies the input for explanation, without influencing trust or the verdict.</summary>
        public string ContentName { get; set; } = string.Empty;
        /// <summary>Explains the result and any coverage limitation to the user.</summary>
        public string Details { get; set; } = string.Empty;
        /// <summary>Measures the completed native and local inspection work for this request.</summary>
        public TimeSpan ScanDuration { get; set; }
    }

    public interface IAmsiScanService : IDisposable
    {
        bool IsAmsiSupported { get; }
        Task<AmsiScanResult> ScanStringAsync(string content, string contentName = "DynamicScript");
        Task<AmsiScanResult> ScanBufferAsync(byte[] buffer, string contentName = "MemoryBuffer");
    }
}
