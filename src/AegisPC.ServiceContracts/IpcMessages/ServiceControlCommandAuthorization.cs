namespace AegisPC.ServiceContracts.IpcMessages;

/// <summary>Maps ordinary service controls to the existing verified-caller role; vault/inventory commands use their separate ownership policy.</summary>
public static class ServiceControlCommandAuthorization
{
    /// <summary>Allows defined ordinary controls only to an authenticated administrator, except read-only status; a caller-provided role must never be used here.</summary>
    public static bool IsAllowed(ServiceCommandType commandType, bool verifiedAdministrator) =>
        Enum.IsDefined(commandType) && (commandType == ServiceCommandType.GetStatus || verifiedAdministrator);
}
