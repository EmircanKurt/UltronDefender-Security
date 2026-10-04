using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models.Devices;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime;

public partial class RealTimeProtectionEngine : IRemovableMediaProtection
{
    private readonly Dictionary<Guid, string> _mediaRoots = new();
    private readonly SemaphoreSlim _backgroundInspectionGate = new(1, 1);
    private IScanResourceManager? _backgroundResources;
    private readonly Dictionary<Guid, MediaInspectionSnapshot> _mediaInspections = new();
    private readonly Dictionary<Guid, CancellationTokenSource> _mediaCancellations = new();

    /// <inheritdoc />
    public IReadOnlyList<MediaInspectionSnapshot> GetMediaInspections()
    { lock (_lock) return _mediaInspections.Values.Select(x => x with { Limitations = x.Limitations.ToArray() }).ToArray(); }

    /// <inheritdoc />
    public async Task InspectMediaAsync(string volumePath, Guid insertionGeneration, CancellationToken cancellationToken)
    {
        string root = Path.GetFullPath(volumePath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        CancellationTokenSource linked;
        lock (_lock)
        {
            if (!_isRunning || _engineCts == null) throw new InvalidOperationException("File protection is not running.");
            cancellationToken.ThrowIfCancellationRequested();
            if (_mediaCancellations.ContainsKey(insertionGeneration)) throw new InvalidOperationException("This insertion is already being inspected.");
            AttachWatcher(root);
            if (!_watchedLocationsList.Contains(root, StringComparer.OrdinalIgnoreCase))
                throw new IOException("Media watcher could not be attached; initial inspection was not declared active.");
            _mediaRoots[insertionGeneration] = root;
            _mediaInspections[insertionGeneration] = new() { VolumeGuid = root, Generation = insertionGeneration };
            linked = CancellationTokenSource.CreateLinkedTokenSource(_engineCts.Token, cancellationToken);
            _mediaCancellations[insertionGeneration] = linked;
        }
        try
        {
            UpdateMedia(insertionGeneration, x => x with { State = "Scanning" });
            bool complete = await BoundedDirectoryInspection.WalkAsync(root, async (file, token) =>
            {
                bool inspected = await InspectBackgroundFileWithOutcomeAsync(file, token).ConfigureAwait(false);
                UpdateMedia(insertionGeneration, x => x with { AttemptedFiles = x.AttemptedFiles + 1,
                    IncompleteFiles = x.IncompleteFiles + (inspected ? 0 : 1) });
            }, reason => UpdateMedia(insertionGeneration, x => x with
                { Limitations = x.Limitations.Append(reason).Distinct().Take(16).ToArray() }), linked.Token).ConfigureAwait(false);
            UpdateMedia(insertionGeneration, x => x with { State = complete && x.IncompleteFiles == 0 ? "Completed" : "Partial" });
            _logger?.LogInformation("Initial media inspection finished for insertion {Generation}; traversal complete {Complete}. This is not firmware verification.", insertionGeneration, complete);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        { UpdateMedia(insertionGeneration, x => x with { State = "Cancelled" }); throw; }
        catch
        { UpdateMedia(insertionGeneration, x => x with { State = "Partial", Limitations = ["InitialInspectionFailed"] }); throw; }
        finally
        {
            lock (_lock)
                if (_mediaCancellations.TryGetValue(insertionGeneration, out var current) && ReferenceEquals(current, linked))
                    _mediaCancellations.Remove(insertionGeneration);
            linked.Dispose();
        }
    }

    /// <inheritdoc />
    public void RemoveMedia(Guid insertionGeneration)
    {
        lock (_lock)
        {
            if (_mediaCancellations.TryGetValue(insertionGeneration, out var pending)) pending.Cancel();
            if (!_mediaRoots.Remove(insertionGeneration, out var root)) return;
            _mediaInspections.Remove(insertionGeneration);
            // A recycled mount or GUID may already belong to a newer insertion.
            if (!_mediaRoots.Values.Contains(root, StringComparer.OrdinalIgnoreCase)) RemoveWatchDirectory(root);
        }
    }

    private void UpdateMedia(Guid generation, Func<MediaInspectionSnapshot, MediaInspectionSnapshot> update)
    { lock (_lock) if (_mediaInspections.TryGetValue(generation, out var snapshot)) _mediaInspections[generation] = update(snapshot); }

    private async Task InspectBackgroundFileAsync(string file, CancellationToken token)
    {
        if (!await InspectBackgroundFileWithOutcomeAsync(file, token).ConfigureAwait(false) && !token.IsCancellationRequested)
            lock (_lock) _coverageDegraded = true;
    }

    private async Task<bool> InspectBackgroundFileWithOutcomeAsync(string file, CancellationToken token)
    {
        // One cooperative background file at a time, releasing between files so another media or
        // reconciliation cursor can progress. Real-time arrival workers do not use this gate.
        await _backgroundInspectionGate.WaitAsync(token).ConfigureAwait(false);
        bool acquired = false;
        try
        {
            if (_backgroundResources != null)
            { await _backgroundResources.EnterWorkerSlotAsync(token).ConfigureAwait(false); acquired = true; }
            return await HandleNormalizedEventAsync(new NormalizedFileEvent
            {
                EventType = RealTimeEventType.Modified, FilePath = file,
                NormalizedPath = Path.GetFullPath(file), Extension = Path.GetExtension(file), Timestamp = DateTime.UtcNow
            }, token).ConfigureAwait(false);
        }
        finally
        {
            try { if (acquired) _backgroundResources!.ExitWorkerSlot(); }
            finally { _backgroundInspectionGate.Release(); }
        }
    }
}
