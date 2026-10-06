namespace AegisPC.Core.Enums
{
    /// <summary>
    /// Gerçek zamanlı koruma dosya analiz karar durumu (Dosyanın ne olduğunu belirtir).
    /// </summary>
    public enum RealTimeVerdict
    {
        Clean,
        Suspicious,
        ConfirmedMalicious,
        /// <summary>Inspection failed or could not establish a verdict; never represents clean content.</summary>
        Unknown
    }
}
