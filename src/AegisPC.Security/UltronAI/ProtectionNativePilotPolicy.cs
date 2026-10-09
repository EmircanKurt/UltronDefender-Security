namespace AegisPC.Security.UltronAI;

/// <summary>
/// Keeps native automatic containment closed until the broker owns a validated target lease,
/// vault handover and Windows VM gates. Settings or asserted verdicts cannot enable this capability.
/// </summary>
public static class ProtectionNativePilotPolicy
{
    /// <summary>Native containment is unavailable in the current observation-only production composition.</summary>
    public static bool AutomaticContainmentAvailable => false;
    /// <summary>Reason returned instead of claiming that an unavailable action succeeded.</summary>
    public const string ReasonCode = "BrokerNativeTargetLeaseAndVmGatePending";
}
