using System;

namespace AegisPC.Core.Models;

/// <summary>Identifies the scan operation that could not finish; observer failures are not scan failures.</summary>
public enum ScanFailureStage
{
    /// <summary>The owned resource profile could not be applied before scanning.</summary>
    Preparation = 0,
    /// <summary>The scanner could not produce a terminal inspection result.</summary>
    Scanning = 1,
    /// <summary>Applying the configured finding policy interrupted result processing.</summary>
    PolicyEnforcement = 2,
    /// <summary>An external scanner released its ownership without reporting an outcome.</summary>
    ExternalScanner = 3
}

/// <summary>Stable machine-readable causes, independent of localized text or private exception messages.</summary>
public enum ScanFailureReason
{
    /// <summary>An unexpected exception interrupted the owned operation.</summary>
    UnexpectedException = 0,
    /// <summary>The scanner returned null instead of a result.</summary>
    MissingResult = 1,
    /// <summary>The scanner explicitly returned a failed result without further failure details.</summary>
    ScannerReportedFailure = 2,
    /// <summary>An operation cancelled while the owned session token was still active.</summary>
    UnexpectedCancellation = 3,
    /// <summary>The scanner channel closed while the owned session token was still active.</summary>
    ChannelClosed = 4,
    /// <summary>The scanner returned a nonterminal or unrecognized lifecycle status.</summary>
    InvalidResultStatus = 5,
    /// <summary>External ownership ended before a result was reported.</summary>
    ExternalScannerAbandoned = 6
}

/// <summary>Privacy-safe diagnostics retained with a failed scan and its persisted report.</summary>
public sealed class ScanFailureInfo
{
    /// <summary>The operation whose failure ended the scan.</summary>
    public ScanFailureStage Stage { get; set; }
    /// <summary>The typed failure cause; consumers must not classify errors by message text.</summary>
    public ScanFailureReason Reason { get; set; }
    /// <summary>The native error code when the exception explicitly supplies one.</summary>
    public int? NativeErrorCode { get; set; }
    /// <summary>The exception HResult when an exception caused the failure.</summary>
    public int? HResult { get; set; }
    /// <summary>A bounded explanation containing no paths, command lines, or raw exception text.</summary>
    public string SafeMessage { get; set; } = string.Empty;
    /// <summary>The UTC instant when the terminal failure was observed.</summary>
    public DateTime OccurredAtUtc { get; set; }
    /// <summary>The owning scan identity used to correlate diagnostics without exposing a target path.</summary>
    public Guid CorrelationId { get; set; }
    /// <summary>Whether a new scan can be attempted; this never requests an automatic retry.</summary>
    public bool IsRetryable { get; set; }
}
