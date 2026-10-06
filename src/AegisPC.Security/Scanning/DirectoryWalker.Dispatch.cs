using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Helpers;
using Serilog;

namespace AegisPC.Security.Scanning;

public partial class DirectoryWalker
{
    private bool IsEligibleImplicitTarget(string path)
    {
        if (ImplicitLocalPathPolicy.IsEligible(path)) return true;
        _coverage.Value?.RecordLimitation("ImplicitNonLocalOrReparseTargetNotInspected");
        return false;
    }

    private Task DispatchImplicitInspectionFileAsync(string file, Func<string, Task> enqueue, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return IsEligibleImplicitTarget(file) ? DispatchInspectionFileAsync(file, enqueue, ct) : Task.CompletedTask;
    }

    private Task EnumerateImplicitDirectoryAsync(string path, bool recursive, Func<string, Task> enqueue,
        CancellationToken ct, ManualResetEventSlim? pauseEvent)
    {
        ct.ThrowIfCancellationRequested();
        return IsEligibleImplicitTarget(path)
            ? EnumerateDirectorySafelyAsync(path, recursive, enqueue, ct, pauseEvent) : Task.CompletedTask;
    }

    private async Task DispatchInspectionFileAsync(string file, Func<string, Task> enqueue, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
            { _coverage.Value?.RecordReparseSkip(); return; }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            _coverage.Value?.RecordLimitation("FileAttributesUnavailableBeforeQueueing");
            Log.Debug(exception, "File attributes could not be read before queue dispatch.");
            return;
        }
        try { await enqueue(file).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (ScanQueueDispatchException) { throw; }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        { throw new ScanQueueDispatchException(exception); }
    }

    private sealed class ScanQueueDispatchException(Exception inner)
        : Exception("The scan queue rejected a file; this is not an enumeration access error.", inner);
}
