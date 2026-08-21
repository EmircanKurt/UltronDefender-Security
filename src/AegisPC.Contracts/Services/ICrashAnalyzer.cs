using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface ICrashAnalyzer
{
    Task<List<CrashEvent>> GetRecentCrashesAsync(TimeSpan timeWindow, CancellationToken cancellationToken = default);
    Task<string> AnalyzeCrashAsync(CrashEvent crashEvent, CancellationToken cancellationToken = default);
    Task<CrashReport> BuildCrashReportAsync(CrashEvent crashEvent, CancellationToken cancellationToken = default);
}
