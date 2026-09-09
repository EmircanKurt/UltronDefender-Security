using System;
using System.Threading;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Represents an active or completed scan session, encapsulating its unique identity,
    /// scan configuration, real-time progress, and execution lifecycle.
    /// </summary>
    public interface IScanSession
    {
        /// <summary>
        /// Unique identifier for this scan session instance.
        /// </summary>
        Guid SessionId { get; }

        /// <summary>
        /// The type of scan being executed (Quick, Full, Custom).
        /// </summary>
        ScanType ScanType { get; }

        /// <summary>
        /// The custom path targeted by this scan session, if applicable.
        /// </summary>
        string CustomPath { get; }

        /// <summary>
        /// UTC timestamp indicating when the scan session began.
        /// </summary>
        DateTime StartedAtUtc { get; }

        /// <summary>
        /// Indicates whether this scan session is currently executing.
        /// </summary>
        bool IsActive { get; }

        /// <summary>
        /// Indicates whether execution of this session has been paused by the user.
        /// </summary>
        bool IsPaused { get; }

        /// <summary>
        /// The latest reported progress telemetry for this session.
        /// </summary>
        ScanProgress? LatestProgress { get; }

        /// <summary>
        /// CancellationToken tied to this session's execution lifecycle.
        /// </summary>
        CancellationToken CancellationToken { get; }

        /// <summary>
        /// Pauses the active scan session.
        /// </summary>
        void Pause();

        /// <summary>
        /// Resumes execution of a paused scan session.
        /// </summary>
        void Resume();

        /// <summary>
        /// Requests cancellation of this scan session.
        /// </summary>
        void Cancel();
    }
}
