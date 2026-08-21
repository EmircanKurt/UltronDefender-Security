using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface ICorrelationEngine
{
    Task CorrelateEventAsync(CrashEvent crashEvent, TimeSpan window, CancellationToken cancellationToken = default);
}
