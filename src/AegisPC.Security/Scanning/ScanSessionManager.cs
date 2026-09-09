using System;
using System.Threading;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Thread-safe coordinator for active scan sessions. Guarantees single active session
    /// semantics across the entire application and notifies subscribers when sessions begin or end.
    /// </summary>
    public class ScanSessionManager : IScanSessionManager
    {
        private readonly object _lock = new();
        private readonly ILogger<ScanSessionManager>? _logger;
        private ScanSession? _currentSession;

        public IScanSession? CurrentSession
        {
            get
            {
                lock (_lock) return _currentSession;
            }
        }

        public event Action<IScanSession>? ScanSessionStarted;
        public event Action<IScanSession, ScanResult>? ScanSessionEnded;

        public ScanSessionManager(ILogger<ScanSessionManager>? logger = null)
        {
            _logger = logger;
        }

        public IScanSession GetOrCreateSession(ScanType scanType, string customPath, out bool isNewSession)
        {
            lock (_lock)
            {
                if (_currentSession != null && _currentSession.IsActive)
                {
                    isNewSession = false;
                    _logger?.LogInformation("Returning active scan session {SessionId} ({Type})", _currentSession.SessionId, _currentSession.ScanType);
                    return _currentSession;
                }

                var cts = new CancellationTokenSource();
                var session = new ScanSession(
                    scanType,
                    customPath,
                    cts,
                    () => { }, // Delegated to coordinator
                    () => { },
                    () => { });

                _currentSession = session;
                isNewSession = true;
                _logger?.LogInformation("Created new scan session {SessionId} for {ScanType}", session.SessionId, scanType);
            }

            return _currentSession;
        }

        public void NotifySessionStarted(IScanSession session)
        {
            try
            {
                ScanSessionStarted?.Invoke(session);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error dispatching ScanSessionStarted event.");
            }
        }

        public void CompleteSession(Guid sessionId, ScanResult result)
        {
            IScanSession? sessionToNotify = null;
            lock (_lock)
            {
                if (_currentSession != null && _currentSession.SessionId == sessionId)
                {
                    _currentSession.MarkEnded();
                    sessionToNotify = _currentSession;
                    _currentSession = null;
                }
            }

            if (sessionToNotify != null)
            {
                try
                {
                    ScanSessionEnded?.Invoke(sessionToNotify, result);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Error dispatching ScanSessionEnded event.");
                }
            }
        }
    }
}
