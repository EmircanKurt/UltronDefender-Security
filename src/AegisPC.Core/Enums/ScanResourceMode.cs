namespace AegisPC.Core.Enums
{
    /// <summary>
    /// User-selectable and adaptive scan resource consumption modes.
    /// Controls background CPU utilization, worker concurrency, memory footprints, and disk pacing.
    /// </summary>
    public enum ScanResourceMode
    {
        /// <summary>
        /// Automatically adjusts scanning aggression based on real-time system pressure,
        /// foreground user activity, laptop battery status, and hardware profile.
        /// </summary>
        Auto,

        /// <summary>
        /// Minimum resource footprint: 1 worker, low memory ceiling, deliberate pacing delays.
        /// Zero impact on gaming, rendering, or daily responsiveness.
        /// </summary>
        VeryLow,

        /// <summary>
        /// Gentle background scanning: 2 workers, conservative batching, frequent cooperative yields.
        /// </summary>
        Low,

        /// <summary>
        /// Standard default balance between scan throughput and system responsiveness.
        /// </summary>
        Balanced,

        /// <summary>
        /// High performance: increased worker parallelism, larger buffers, minimal throttling.
        /// </summary>
        High,

        /// <summary>
        /// Maximum scan speed: all eligible cores engaged, highest throughput.
        /// Recommended when system is idle or during dedicated security maintenance.
        /// </summary>
        Maximum
    }
}
