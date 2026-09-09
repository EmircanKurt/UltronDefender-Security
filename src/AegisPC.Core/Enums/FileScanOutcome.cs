namespace AegisPC.Core.Enums
{
    /// <summary>
    /// Represents the definitive operational outcome of scanning an individual file.
    /// </summary>
    public enum FileScanOutcome
    {
        /// <summary>
        /// File was analyzed successfully without unhandled errors or timeouts.
        /// </summary>
        Success,

        /// <summary>
        /// File analysis failed due to I/O error, corrupted structure, or exception.
        /// </summary>
        Failed,

        /// <summary>
        /// File analysis exceeded the allowed per-file execution budget and was aborted.
        /// </summary>
        Timeout,

        /// <summary>
        /// File was skipped deliberately (e.g. self-protection, zero length, safe media filter).
        /// </summary>
        Skipped
    }
}
