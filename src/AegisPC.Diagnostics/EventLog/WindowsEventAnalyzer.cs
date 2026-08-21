using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Diagnostics.EventLog
{
    public class WindowsEventAnalyzer : IWindowsEventAnalyzer, IDisposable
    {
        private readonly ILogger<WindowsEventAnalyzer>? _logger;
        private EventLogWatcher? _appWatcher;
        private EventLogWatcher? _systemWatcher;
        private Action<WindowsEventEntry>? _onEventReceived;

        public WindowsEventAnalyzer(ILogger<WindowsEventAnalyzer>? logger = null)
        {
            _logger = logger;
        }

        public Task<List<WindowsEventEntry>> GetRecentEventsAsync(TimeSpan timeWindow, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var events = new List<WindowsEventEntry>();
                long milliseconds = (long)timeWindow.TotalMilliseconds;
                if (milliseconds <= 0) milliseconds = 86400000; // default 24h

                // Read both Application and System logs for Error (Level=2) and Critical (Level=1)
                var channels = new[] { "Application", "System" };
                foreach (var channel in channels)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    try
                    {
                        string query = $"*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]";
                        var logQuery = new EventLogQuery(channel, PathType.LogName, query);
                        using var reader = new EventLogReader(logQuery);

                        for (EventRecord record = reader.ReadEvent(); record != null; record = reader.ReadEvent())
                        {
                            using (record)
                            {
                                if (cancellationToken.IsCancellationRequested) break;

                                events.Add(MapEventRecord(record, channel));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogWarning(ex, "Failed to read event log channel {Channel}", channel);
                    }
                }

                events.Sort((a, b) => b.TimeCreated.CompareTo(a.TimeCreated));
                return events;
            }, cancellationToken);
        }

        public Task<List<WindowsEventEntry>> GetEventsByTypeAsync(string logName, int eventId, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var events = new List<WindowsEventEntry>();
                try
                {
                    string query = $"*[System[EventID={eventId}]]";
                    var logQuery = new EventLogQuery(logName, PathType.LogName, query);
                    using var reader = new EventLogReader(logQuery);

                    for (EventRecord record = reader.ReadEvent(); record != null; record = reader.ReadEvent())
                    {
                        using (record)
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            events.Add(MapEventRecord(record, logName));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to read event log channel {LogName} for EventId {Id}", logName, eventId);
                }

                events.Sort((a, b) => b.TimeCreated.CompareTo(a.TimeCreated));
                return events;
            }, cancellationToken);
        }

        public void WatchForNewEvents(Action<WindowsEventEntry> onEventReceived)
        {
            _onEventReceived = onEventReceived;
            try
            {
                var appQuery = new EventLogQuery("Application", PathType.LogName, "*[System[(Level=1 or Level=2)]]");
                _appWatcher = new EventLogWatcher(appQuery);
                _appWatcher.EventRecordWritten += (s, e) =>
                {
                    if (e.EventRecord != null)
                    {
                        var entry = MapEventRecord(e.EventRecord, "Application");
                        _onEventReceived?.Invoke(entry);
                    }
                };
                _appWatcher.Enabled = true;

                var sysQuery = new EventLogQuery("System", PathType.LogName, "*[System[(Level=1 or Level=2)]]");
                _systemWatcher = new EventLogWatcher(sysQuery);
                _systemWatcher.EventRecordWritten += (s, e) =>
                {
                    if (e.EventRecord != null)
                    {
                        var entry = MapEventRecord(e.EventRecord, "System");
                        _onEventReceived?.Invoke(entry);
                    }
                };
                _systemWatcher.Enabled = true;
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Could not start EventLogWatcher. Real-time logging may require admin rights.");
            }
        }

        private static WindowsEventEntry MapEventRecord(EventRecord record, string logName)
        {
            string description = string.Empty;
            try { description = record.FormatDescription() ?? string.Empty; } catch { }

            string xml = string.Empty;
            try { xml = record.ToXml(); } catch { }

            return new WindowsEventEntry
            {
                LogName = logName,
                ProviderName = record.ProviderName ?? "Unknown",
                EventId = record.Id,
                Level = record.Level switch
                {
                    1 => "Kritik",
                    2 => "Hata",
                    3 => "Uyarı",
                    4 => "Bilgi",
                    5 => "Ayrıntılı",
                    _ => "Bilgi"
                },
                Message = description,
                TimeCreated = record.TimeCreated ?? DateTime.UtcNow,
                MachineName = record.MachineName ?? Environment.MachineName,
                ProcessId = record.ProcessId,
                RawXml = xml
            };
        }

        public void Dispose()
        {
            if (_appWatcher != null)
            {
                _appWatcher.Enabled = false;
                _appWatcher.Dispose();
            }
            if (_systemWatcher != null)
            {
                _systemWatcher.Enabled = false;
                _systemWatcher.Dispose();
            }
        }
    }
}
