using System.Diagnostics;
using Microsoft.Win32.SafeHandles;

namespace Ultron.PortableInspection;

/// <summary>Visits only an explicit selected Linux scope using descriptor-relative, read-only, bounded access.</summary>
public sealed class ManualScopeScanner(PreviewInspector inspector, InspectionLimits? limits = null)
{
    private readonly InspectionLimits _limits = limits ?? new();

    /// <summary>Returns reports for regular files; links, special nodes, errors and omitted scope remain incomplete.</summary>
    public async Task<IReadOnlyList<InspectionReport>> ScanAsync(string selectedPath, ScanControl control,
        IProgress<InspectionReport>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(control);
        _limits.Validate();
        var state = new Session(progress);
        try
        {
            using var selected = LinuxFileAccess.OpenSelectedPath(selectedPath);
            var metadata = LinuxFileAccess.Metadata(selected);
            state.Visited = 1;
            await VisitAsync(Path.GetFullPath(selectedPath), selected, metadata, metadata, 0, state, control, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException or EntryPointNotFoundException or DllNotFoundException)
        { state.Add(new() { Path = selectedPath, Limitations = [ex.Message] }); }
        return state.Reports;
    }

    private async Task VisitAsync(string path, SafeFileHandle node, FileMetadata metadata, FileMetadata root,
        int depth, Session state, ScanControl control, CancellationToken ct)
    {
        await control.WaitAsync(ct);
        if (depth > 32 || state.Clock.Elapsed > TimeSpan.FromMinutes(15))
        { state.Add(new() { Path = path, Limitations = ["Manual scope path, depth or elapsed time budget was reached."] }); return; }
        if (!metadata.SameDevice(root))
        { state.Add(new() { Path = path, Limitations = ["Cross-device traversal is unsupported by this preview."] }); return; }
        if (metadata.IsRegularFile)
        {
            state.Add(await InspectFileAsync(path, node, metadata, state, ct));
            return;
        }
        if (!metadata.IsDirectory)
        { state.Add(new() { Path = path, Limitations = ["Non-regular node (device, FIFO, socket or link) is unsupported and was not read."] }); return; }
        await VisitDirectoryAsync(path, node, metadata, root, depth, state, control, ct);
    }

    private async Task VisitDirectoryAsync(string path, SafeFileHandle node, FileMetadata metadata, FileMetadata root,
        int depth, Session state, ScanControl control, CancellationToken ct)
    {
        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(LinuxFileAccess.EnumerationPath(node)))
            {
                ct.ThrowIfCancellationRequested();
                if (state.Visited >= _limits.MaximumPaths || state.Clock.Elapsed > TimeSpan.FromMinutes(15))
                { state.Add(new() { Path = path, Limitations = ["Manual scope budget was reached; remaining directory entries were not inspected."] }); break; }
                string name = Path.GetFileName(entry);
                string childPath = Path.Combine(path, name);
                state.Visited++;
                try
                {
                    using var child = LinuxFileAccess.OpenChild(node, name);
                    await VisitAsync(childPath, child, LinuxFileAccess.Metadata(child), root, depth + 1, state, control, ct);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { state.Add(new() { Path = childPath, Limitations = [ex.Message] }); }
            }
            if (metadata != LinuxFileAccess.Metadata(node))
                state.Add(new() { Path = path, Limitations = ["Directory metadata changed during traversal; scope completeness is unknown."] });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { state.Add(new() { Path = path, Limitations = ["Directory traversal failed: " + ex.Message] }); }
    }

    private async Task<InspectionReport> InspectFileAsync(string path, SafeFileHandle handle, FileMetadata before, Session state, CancellationToken ct)
    {
        if (before.Size > (ulong)_limits.MaximumFileBytes || !state.ByteBudget.TryReserve(before.Size + 1))
            return new() { Path = path, Limitations = ["File or session byte budget exceeded; contents were not read."] };
        byte[] bytes = new byte[checked((int)before.Size)];
        using var reader = LinuxFileAccess.OpenForRead(handle, before);
        using var stream = new FileStream(reader, FileAccess.Read, 1, isAsync: false);
        await stream.ReadExactlyAsync(bytes.AsMemory(), ct);
        byte[] eofProbe = new byte[1];
        if (await stream.ReadAsync(eofProbe.AsMemory(), ct) != 0)
            return new() { Path = path, Limitations = ["Source contains data beyond its declared size; complete snapshot inspection is unsupported."] };
        if (before != LinuxFileAccess.Metadata(handle))
            return new() { Path = path, Limitations = ["Source changed during snapshot read; inspection was discarded."] };
        var report = await inspector.InspectAsync(path, bytes, _limits, ct);
        return before == LinuxFileAccess.Metadata(handle) ? report
            : new() { Path = path, Limitations = ["Source changed during inspection; the snapshot result was discarded."] };
    }

    private sealed class Session(IProgress<InspectionReport>? progress)
    {
        internal readonly List<InspectionReport> Reports = [];
        internal readonly Stopwatch Clock = Stopwatch.StartNew();
        internal int Visited;
        internal readonly SourceByteBudget ByteBudget = new();
        internal void Add(InspectionReport report) { Reports.Add(report); progress?.Report(report); }
    }
}
