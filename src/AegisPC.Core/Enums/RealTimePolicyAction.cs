namespace AegisPC.Core.Enums
{
    /// <summary>
    /// Gerçek zamanlı koruma politika eylemi (Karara karşı ne yapılacağını belirtir).
    /// </summary>
    public enum RealTimePolicyAction
    {
        Allow,
        Observe,
        Warn,
        BlockAndQuarantine
    }
}
