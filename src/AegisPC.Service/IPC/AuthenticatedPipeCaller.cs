using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace AegisPC.Service.IPC;

/// <summary>Captures the real local pipe token and verifies its session; payloads cannot supply identity.</summary>
internal sealed class AuthenticatedPipeCaller : IDisposable
{
    internal WindowsIdentity Identity { get; }
    internal string Sid { get; }
    internal bool IsAdministrator { get; }
    internal uint SessionId { get; }

    private AuthenticatedPipeCaller(WindowsIdentity identity, uint session)
    {
        Identity = identity;
        Sid = identity.User?.Value ?? throw new UnauthorizedAccessException("The caller SID is unavailable.");
        SessionId = session;
        IsAdministrator = identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    internal static AuthenticatedPipeCaller Capture(NamedPipeServerStream pipe)
    {
        WindowsIdentity? identity = null;
        try
        {
            if (!GetNamedPipeClientSessionId(pipe.SafePipeHandle, out uint pipeSession)) throw new Win32Exception(Marshal.GetLastWin32Error());
            pipe.RunAsClient(() => identity = WindowsIdentity.GetCurrent());
            if (identity == null || !identity.IsAuthenticated || identity.IsAnonymous || identity.User == null)
                throw new UnauthorizedAccessException("An authenticated local caller token is required.");
            // Identification is deliberately sufficient for authorization, but never for file I/O.
            // Asking for Impersonation on the public discovery pipe would expose the UI token to a squatter.
            if (identity.ImpersonationLevel < TokenImpersonationLevel.Identification)
                throw new UnauthorizedAccessException("The local caller token cannot be identified.");
            if (!GetTokenInformation(identity.AccessToken, 12, out uint tokenSession, sizeof(uint), out _) || tokenSession != pipeSession)
                throw new UnauthorizedAccessException("The pipe and token sessions do not match.");
            var caller = new AuthenticatedPipeCaller(identity, pipeSession);
            identity = null;
            return caller;
        }
        finally { identity?.Dispose(); }
    }

    public void Dispose() => Identity.Dispose();

    internal bool CanPerformCallerContextIo => Identity.ImpersonationLevel >= TokenImpersonationLevel.Impersonation;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientSessionId(SafePipeHandle pipe, out uint session);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, out uint information, int length, out int returned);
}
