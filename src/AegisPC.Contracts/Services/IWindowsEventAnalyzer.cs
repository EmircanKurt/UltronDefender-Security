using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services;

public interface IWindowsEventAnalyzer
{
    Task<List<WindowsEventEntry>> GetRecentEventsAsync(TimeSpan timeWindow, CancellationToken cancellationToken = default);
    Task<List<WindowsEventEntry>> GetEventsByTypeAsync(string logName, int eventId, CancellationToken cancellationToken = default);
    void WatchForNewEvents(Action<WindowsEventEntry> onEventReceived);
}
