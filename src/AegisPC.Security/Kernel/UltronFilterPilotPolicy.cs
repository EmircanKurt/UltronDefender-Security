namespace AegisPC.Security.Kernel;

/// <summary>
/// Records the deliberately closed native enforcement gate. Legacy path/PID messages do not
/// identify an immutable file stream or prove that a kernel decision was applied.
/// </summary>
public static class UltronFilterPilotPolicy
{
    /// <summary>False until native identity, authenticated peer, signing and VM gates are implemented and verified.</summary>
    public static bool IdentityBoundEnforcementAvailable => false;

    /// <summary>The unverified legacy native bridge is not activated by an experimental setting alone.</summary>
    public static bool LegacyBridgeActivationAllowed => false;

    /// <summary>
    /// Accepts only a successful, exactly sized canonical legacy boolean reply. This validates framing,
    /// not evidence, authorization or successful enforcement; STATUS_TIMEOUT (0x102) is not a reply.
    /// </summary>
    public static bool IsValidLegacyReply(uint ntStatus, uint returnedBytes, byte blockByte)
        => ntStatus == 0 && returnedBytes == 1 && blockByte <= 1;
}
