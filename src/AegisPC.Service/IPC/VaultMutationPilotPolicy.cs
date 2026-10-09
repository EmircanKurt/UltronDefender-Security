using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.Service.IPC;

/// <summary>Caller SID alone cannot authorize vault mutations before authenticated application and interactive approval gates.</summary>
public static class VaultMutationPilotPolicy
{
    /// <summary>True for operations that must remain unavailable on the current read-only pilot transport.</summary>
    public static bool RequiresAuthenticatedApproval(ServiceCommandType command) => command is
        ServiceCommandType.QuarantineFile or ServiceCommandType.RestoreQuarantine or ServiceCommandType.DeleteQuarantine;
}
