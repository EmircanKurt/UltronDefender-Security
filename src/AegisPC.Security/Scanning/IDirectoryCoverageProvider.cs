using System;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Associates traversal coverage with one async scan session.</summary>
public interface IDirectoryCoverageProvider
{
    /// <summary>Begins a scope whose observations cannot overwrite another session's summary.</summary>
    IDisposable BeginCoverage(ScanCoverageSummary summary);
}
