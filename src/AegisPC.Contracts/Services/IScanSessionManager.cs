using System;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Coordinates scan sessions across UI components, background services, tray, and IPC,
    /// preventing duplicate concurrent scans and ensuring consistent lifecycle management.
    /// </summary>
    public interface IScanSessionManager
    {
        /// <summary>
        /// The currently active scan session, or null if no scan is in progress.
        /// </summary>
        IScanSession? CurrentSession { get; }

        /// <summary>
        /// Fired when a new scan session is initialized and begins executing.
        /// </summary>
        event Action<IScanSession>? ScanSessionStarted;

        /// <summary>
        /// Fired when a scan session finishes execution (completed, cancelled, or failed).
        /// </summary>
        event Action<IScanSession, ScanResult>? ScanSessionEnded;

        /// <summary>
        /// Gets the currently running scan session if one exists; otherwise initializes a new session.
        /// Guaranteed to be thread-safe and non-duplicating.
        /// </summary>
        /// <param name="scanType">The type of scan requested.</param>
        /// <param name="customPath">The target directory or file path for custom scans.</param>
        /// <param name="isNewSession">Outputs true if a new session was created; false if returning existing active session.</param>
        /// <returns>The active or newly created scan session.</returns>
        IScanSession GetOrCreateSession(ScanType scanType, string customPath, out bool isNewSession);

        /// <summary>
        /// Marks the designated scan session as completed.
        /// </summary>
        void CompleteSession(Guid sessionId, ScanResult result);
    }
}
