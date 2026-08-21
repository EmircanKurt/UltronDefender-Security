using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Diagnostics.Correlation;
using AegisPC.Diagnostics.EventLog;
using Microsoft.Extensions.Logging;

namespace AegisPC.Diagnostics.Crash
{
    public class CrashAnalyzer : ICrashAnalyzer
    {
        private readonly IWindowsEventAnalyzer _eventAnalyzer;
        private readonly ICorrelationEngine _correlationEngine;
        private readonly ILogger<CrashAnalyzer>? _logger;

        public CrashAnalyzer(
            IWindowsEventAnalyzer eventAnalyzer,
            ICorrelationEngine correlationEngine,
            ILogger<CrashAnalyzer>? logger = null)
        {
            _eventAnalyzer = eventAnalyzer;
            _correlationEngine = correlationEngine;
            _logger = logger;
        }

        public async Task<List<CrashEvent>> GetRecentCrashesAsync(TimeSpan timeWindow, CancellationToken cancellationToken = default)
        {
            var rawEvents = await _eventAnalyzer.GetRecentEventsAsync(timeWindow, cancellationToken);
            var crashes = new List<CrashEvent>();

            foreach (var evt in rawEvents)
            {
                // Inspect EventIDs: 1000 (App Error), 1002 (App Hang), 1001 (WER), 41 (Kernel-Power)
                if (evt.EventId == 1000 || evt.EventId == 1002 || evt.EventId == 1001 || evt.EventId == 41)
                {
                    var (type, appName, exceptionCode, confidence) = EventPatternMatcher.MatchCrashPattern(
                        evt.ProviderName,
                        evt.EventId,
                        evt.Message,
                        evt.RawXml);

                    var crashEvent = new CrashEvent
                    {
                        EventType = type,
                        ApplicationName = appName,
                        EventId = evt.EventId,
                        ProviderName = evt.ProviderName,
                        OccurredAt = evt.TimeCreated,
                        ExceptionCode = exceptionCode,
                        RawEventData = evt.Message,
                        ConfidenceLevel = confidence
                    };

                    await _correlationEngine.CorrelateEventAsync(crashEvent, TimeSpan.FromSeconds(60), cancellationToken);
                    crashes.Add(crashEvent);
                }
            }

            return crashes;
        }

        public async Task<string> AnalyzeCrashAsync(CrashEvent crashEvent, CancellationToken cancellationToken = default)
        {
            await _correlationEngine.CorrelateEventAsync(crashEvent, TimeSpan.FromSeconds(60), cancellationToken);
            return crashEvent.AnalysisResult ?? "Ek telemetri verisi bulunamadı.";
        }

        public async Task<CrashReport> BuildCrashReportAsync(CrashEvent crashEvent, CancellationToken cancellationToken = default)
        {
            await _correlationEngine.CorrelateEventAsync(crashEvent, TimeSpan.FromSeconds(60), cancellationToken);
            return CrashReportBuilder.Build(crashEvent);
        }
    }
}
