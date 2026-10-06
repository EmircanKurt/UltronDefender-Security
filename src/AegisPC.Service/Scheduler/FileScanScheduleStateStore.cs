using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Service.Scheduler;

/// <summary>Stores successful scan completion timestamps independently of user-facing preferences.</summary>
public sealed class ScanScheduleState
{
    /// <summary>Gets or sets the format version; unknown versions must not be overwritten.</summary>
    public int Version { get; set; } = 1;
    /// <summary>Gets or sets the last successfully completed scheduled scan time in UTC.</summary>
    public DateTime? ScheduledScanCompletedUtc { get; set; }
    /// <summary>Gets or sets the last successfully completed idle scan time in UTC.</summary>
    public DateTime? IdleScanCompletedUtc { get; set; }
}

/// <summary>Persists scheduler-owned timestamps without saving or overwriting interactive user settings.</summary>
public interface IScanScheduleStateStore
{
    /// <summary>Loads the last committed state or backup; invalid snapshots are reported to the caller.</summary>
    ScanScheduleState Load();
    /// <summary>Durably publishes completion timestamps while preserving the previous snapshot on failure.</summary>
    Task SaveAsync(ScanScheduleState state, CancellationToken cancellationToken = default);
}

/// <summary>Uses a flushed temporary file and atomic replacement for small, service-owned scheduler state.</summary>
public sealed class FileScanScheduleStateStore : IScanScheduleStateStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Creates a ProgramData state store, or uses an explicitly supplied isolated path for tests.</summary>
    public FileScanScheduleStateStore(string? statePath = null)
    {
        _path = Path.GetFullPath(statePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "UltronDefender", "scheduler-state.json"));
    }

    /// <inheritdoc />
    public ScanScheduleState Load()
    {
        _gate.Wait();
        try
        {
            if (!File.Exists(_path)) return File.Exists(_path + ".bak") ? Read(_path + ".bak") : new();
            try { return Read(_path); }
            catch (JsonException ex) when (File.Exists(_path + ".bak"))
            {
                Trace.TraceWarning("Scheduler state JSON is invalid; loading the committed backup: {0}", ex.Message);
                return Read(_path + ".bak");
            }
        }
        finally { _gate.Release(); }
    }

    private static ScanScheduleState Read(string path)
    {
        var state = JsonSerializer.Deserialize<ScanScheduleState>(File.ReadAllText(path))
            ?? throw new JsonException("Scheduler state contains no snapshot.");
        if (state.Version != 1) throw new InvalidDataException("Unsupported scheduler state version.");
        if (state.ScheduledScanCompletedUtc is DateTime scheduled) state.ScheduledScanCompletedUtc = DateTime.SpecifyKind(scheduled, DateTimeKind.Utc);
        if (state.IdleScanCompletedUtc is DateTime idle) state.IdleScanCompletedUtc = DateTime.SpecifyKind(idle, DateTimeKind.Utc);
        return state;
    }

    /// <inheritdoc />
    public async Task SaveAsync(ScanScheduleState state, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.Version != 1) throw new InvalidDataException("Unsupported scheduler state version.");
        await _gate.WaitAsync(cancellationToken);
        string temporaryPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, state, cancellationToken: cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(_path)) File.Replace(temporaryPath, _path, _path + ".bak");
            else File.Move(temporaryPath, _path);
        }
        finally
        {
            try { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
            finally { _gate.Release(); }
        }
    }
}
