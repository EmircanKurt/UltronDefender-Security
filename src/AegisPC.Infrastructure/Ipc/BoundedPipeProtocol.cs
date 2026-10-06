using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace AegisPC.Infrastructure.Ipc;

/// <summary>Shared local IPC limits; input is bounded before JSON parsing or handler dispatch.</summary>
public static class BoundedPipeProtocol
{
    /// <summary>Maximum UTF-16 character count accepted for one newline-delimited command.</summary>
    public const int MaximumCommandCharacters = 65_536;

    /// <summary>Creates a protected DACL allowing local authenticated clients, but rejecting network logons.</summary>
    public static PipeSecurity CreateLocalSecurity(bool allowAuthenticatedUsers = true)
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        var clientSid = allowAuthenticatedUsers
            ? new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null)
            : WindowsIdentity.GetCurrent().User;
        if (clientSid != null)
            security.AddAccessRule(new PipeAccessRule(clientSid, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize,
                AccessControlType.Allow));
        return security;
    }

    /// <summary>
    /// Reads one frame without unbounded allocation. Idle connections may wait; after the first character,
    /// the complete frame must arrive within ten seconds. Oversized or unterminated frames fail closed.
    /// </summary>
    public static async Task<string?> ReadCommandAsync(TextReader reader, CancellationToken cancellationToken,
        int maximumCharacters = MaximumCommandCharacters)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumCharacters, 1);
        var buffer = new char[1];
        var builder = new StringBuilder(Math.Min(maximumCharacters, 1024));
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), deadline.Token).ConfigureAwait(false);
            if (read == 0)
            {
                if (builder.Length != 0) throw new InvalidDataException("IPC frame ended before its newline delimiter.");
                return null;
            }
            if (builder.Length == 0) deadline.CancelAfter(TimeSpan.FromSeconds(10));
            if (buffer[0] == '\n') return builder.ToString().TrimEnd('\r');
            if (builder.Length >= maximumCharacters) throw new InvalidDataException("IPC command exceeds the permitted size.");
            builder.Append(buffer[0]);
        }
    }
}
