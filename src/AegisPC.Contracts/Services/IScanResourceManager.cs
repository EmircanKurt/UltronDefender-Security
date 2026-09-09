using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Services
{
    /// <summary>
    /// Governs scan resource profiles, live concurrency slots, and cooperative CPU/RAM throttling.
    /// Supports dynamic mid-scan transitions without restarting or dropping items.
    /// </summary>
    public interface IScanResourceManager
    {
        /// <summary>
        /// Current configured resource mode (Auto, VeryLow, Low, Balanced, High, Maximum).
        /// </summary>
        ScanResourceMode CurrentMode { get; }

        /// <summary>
        /// The currently evaluated active resource limits and parameters.
        /// </summary>
        ScanResourceProfile ActiveProfile { get; }

        /// <summary>
        /// Fired when the active resource profile changes either via user selection or automatic adaptation.
        /// </summary>
        event Action<ScanResourceProfile>? ProfileChanged;

        /// <summary>
        /// Updates the current resource mode. If a scan is executing, dynamically adapts worker concurrency.
        /// </summary>
        void SetMode(ScanResourceMode mode);

        /// <summary>
        /// Awaits permission for a worker to process a file, enforcing dynamic concurrency limits.
        /// </summary>
        Task EnterWorkerSlotAsync(CancellationToken cancellationToken);

        /// <summary>
        /// Releases the worker slot upon file completion.
        /// </summary>
        void ExitWorkerSlot();

        /// <summary>
        /// Applies cooperative pacing and delay policies based on active profile settings.
        /// </summary>
        Task ApplyPacingAsync(int processedFileCounter, CancellationToken cancellationToken);

        /// <summary>
        /// Re-evaluates system telemetry and refreshes the active profile (especially in Auto mode).
        /// </summary>
        void RefreshProfile();
    }
}
