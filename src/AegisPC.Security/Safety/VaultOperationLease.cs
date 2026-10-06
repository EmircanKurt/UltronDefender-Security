using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Security.Safety;

/// <summary>Serializes complete vault operations across processes and sessions without thread-affine mutexes over awaits.</summary>
internal sealed class VaultOperationLease : IDisposable
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Gates = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _gate;
    private readonly FileStream _lock;
    private bool _disposed;
    private VaultOperationLease(SemaphoreSlim gate, FileStream fileLock) { _gate = gate; _lock = fileLock; }

    internal static async Task<VaultOperationLease> AcquireAsync(string vault, CancellationToken ct = default, bool customVault = false)
    {
        string canonical = Path.GetFullPath(vault);
        var gate = Gates.GetOrAdd(canonical, _ => new SemaphoreSlim(1, 1));
        if (!await gate.WaitAsync(TimeSpan.FromSeconds(30), ct)) throw new IOException("Vault operation lock timed out.");
        try
        {
            string lockPath = Path.Combine(canonical, "vault.operations.lock");
            if (File.Exists(lockPath) && (File.GetAttributes(lockPath) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Vault operation lock cannot be a reparse point.");
            var elapsed = Stopwatch.StartNew();
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    return new VaultOperationLease(gate, VaultLockFile.Open(lockPath, customVault));
                }
                catch (IOException ex) when (ex.InnerException is Win32Exception native &&
                    native.NativeErrorCode is 32 or 33 && elapsed.Elapsed < TimeSpan.FromSeconds(30))
                { await Task.Delay(25, ct); }
            }
        }
        catch { gate.Release(); throw; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _lock.Dispose();
        _gate.Release();
    }
}
