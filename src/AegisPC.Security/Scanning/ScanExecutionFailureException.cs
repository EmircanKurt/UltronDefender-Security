using System;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Transfers only the failing scanner invocation's partial observations to its coordinator.</summary>
internal sealed class ScanExecutionFailureException : Exception
{
    internal ScanExecutionFailureException(ScanResult partialResult, Exception innerException)
        : base("The scanner ended before producing a terminal result.", innerException)
    {
        PartialResult = partialResult;
    }

    internal ScanResult PartialResult { get; }
}
