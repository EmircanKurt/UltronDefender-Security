using System.Runtime.InteropServices;

namespace Ultron.Linux.App;

// Advisory coordination with the unprivileged remover, not containment or an attacker boundary.
internal sealed class ApplicationLifetimeLease : IDisposable
{
    private readonly FileStream _executable;

    private ApplicationLifetimeLease(FileStream executable) => _executable = executable;

    internal static ApplicationLifetimeLease Acquire()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Application lease requires Linux.");
        string path = Path.Combine(AppContext.BaseDirectory, "Ultron.Linux.App");
        var executable = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        try
        {
            const int sharedNonBlocking = 1 | 4; // Linux LOCK_SH | LOCK_NB; flock(2).
            if (Flock(executable.SafeFileHandle.DangerousGetHandle().ToInt32(), sharedNonBlocking) != 0)
                throw new IOException("Application startup lease failed; removal may be in progress.",
                    new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
            return new ApplicationLifetimeLease(executable);
        }
        catch { executable.Dispose(); throw; }
    }

    /// <summary>Closes the retained executable handle, releasing the advisory startup/removal lease.</summary>
    public void Dispose() => _executable.Dispose();

    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static extern int Flock(int descriptor, int operation);
}
