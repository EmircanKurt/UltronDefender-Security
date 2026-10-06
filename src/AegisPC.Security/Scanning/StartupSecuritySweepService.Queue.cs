using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;
using AegisPC.Security.RealTime;

namespace AegisPC.Security.Scanning;

/// <summary>Owns bounded startup analysis workers while a single consumer aggregates results, actions and progress.</summary>
public partial class StartupSecuritySweepService
{
    private readonly Func<IScanResourceManager>? _resourceManagerFactory;
    private readonly Func<string, bool> _volumeStorageClassifier;
    private IScanResourceManager? _sweepResources;
    private int _sweepWorkers;
    private int _cancellingWorkers;
    private string _workerFile = string.Empty;
    private ScanMeasurementSummary? _sweepMeasurements;
    private sealed record InspectionItem(FileInfo File, RealTimeVerdictResult Verdict, bool FromCache);

    private async IAsyncEnumerable<InspectionItem> InspectCandidatesAsync(IEnumerable<FileInfo> candidates,
        StartupSweepProgress progress, IExternalScanRegistration? registration,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var measurements = new ScanMeasurementRecorder();
        var token = abort.Token;
        var resources = _resourceManagerFactory?.Invoke() ?? new AdaptiveScanResourceManager();
        _sweepResources = resources;
        try
        {
            resources.SetMode(_settingsService?.GetSetting("ScanResourceMode", ScanResourceMode.Auto) ?? ScanResourceMode.Auto);
        }
        catch
        {
            _sweepResources = null;
            if (resources is IDisposable owned) owned.Dispose();
            throw;
        }
        var input = new VolumeScanQueue<FileInfo>(256,
            file => Path.GetPathRoot(file.FullName) ?? "unknown",
            root => _volumeStorageClassifier(root) ? Math.Max(resources.ActiveProfile.Concurrency, resources.ActiveProfile.MaximumConcurrency) : 1);
        var output = Channel.CreateBounded<InspectionItem>(128);
        ExceptionDispatchInfo? failure = null;
        var tasks = new List<Task>();
        void Fail(Exception ex)
        {
            if (ex is OperationCanceledException && cancellationToken.IsCancellationRequested) return;
            Interlocked.CompareExchange(ref failure, ExceptionDispatchInfo.Capture(ex), null);
            try { abort.Cancel(); }
            catch (AggregateException callbackError) { _logger?.LogWarning(callbackError, "Startup cancellation callback failed; original failure retained."); }
        }
        tasks.Add(Task.Run(async () =>
        {
            try
            {
                var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var file in candidates)
                {
                    if (roots.Add(Path.GetPathRoot(file.FullName) ?? "unknown"))
                    {
                        if (roots.Count == 1) resources.ConfigureTarget(file.FullName);
                        else resources.ConfigureMultipleVolumes();
                    }
                    Interlocked.Increment(ref _discoveredFiles);
                    await input.WriteAsync(file, token);
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception ex) { Fail(ex); }
            finally { input.Complete(); }
        }));
        int pool = Math.Max(1, Math.Min(24, Environment.ProcessorCount * 2));
        for (int i = 0; i < pool; i++)
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    while (!token.IsCancellationRequested)
                    {
                        using var volumeLease = await input.ReadAsync(token);
                        if (volumeLease == null) break;
                        var file = volumeLease.Item;
                        while (IsPaused) await Task.Delay(50, token);
                        await RealtimeScanPriority.WaitAsync(token);
                        await resources.EnterWorkerSlotAsync(token);
                        Interlocked.Increment(ref _sweepWorkers);
                        Volatile.Write(ref _workerFile, file.Name);
                        try
                        {
                            await RealtimeScanPriority.WaitAsync(token);
                            using var fileMeasurement = measurements.Begin(file.FullName, volumeLease.QueuedAt);
                            var item = await InspectCandidateAsync(file, progress, registration, token);
                            await output.Writer.WriteAsync(item, token);
                        }
                        finally
                        {
                            Interlocked.Decrement(ref _sweepWorkers);
                            resources.ExitWorkerSlot();
                        }
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { }
                catch (Exception ex) { Fail(ex); }
            }));
        var completion = Task.Run(async () =>
        {
            try { await Task.WhenAll(tasks); }
            catch (Exception ex) { Fail(ex); }
            finally { output.Writer.TryComplete(); }
        });
        try
        {
            while (true)
            {
                var ready = output.Reader.WaitToReadAsync(cancellationToken).AsTask();
                while (!ready.IsCompleted)
                {
                    await Task.WhenAny(ready, Task.Delay(1000));
                    if (!ready.IsCompleted)
                    {
                        progress.CurrentFile = Volatile.Read(ref _workerFile);
                        NotifyProgress(progress, registration, Volatile.Read(ref _cancellingWorkers) > 0
                            ? "Analizin durması bekleniyor; inceleme henüz tamamlanmadı" : null);
                    }
                }
                if (!await ready) break;
                while (output.Reader.TryRead(out var item)) yield return item;
            }
            await completion;
            failure?.Throw();
            cancellationToken.ThrowIfCancellationRequested();
        }
        finally
        {
            try { abort.Cancel(); }
            catch (AggregateException callbackError) { _logger?.LogWarning(callbackError, "Startup cancellation callback failed during cleanup."); }
            await completion;
            _sweepMeasurements = measurements.Snapshot();
            _sweepResources = null;
            if (resources is IDisposable disposable) disposable.Dispose();
        }
    }

    private async Task<InspectionItem> InspectCandidateAsync(FileInfo file, StartupSweepProgress progress,
        IExternalScanRegistration? registration, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (_fileCache.TryGetValue(file.FullName, out var cached) && cached.Verdict == "Clean" &&
            cached.Revision == DetectionPolicyRevision.Current &&
            await HasExpectedContentAsync(file.FullName, cached.SHA256, token) && cached.Revision == DetectionPolicyRevision.Current)
            return new(file, new RealTimeVerdictResult { Verdict = RealTimeVerdict.Clean, SHA256 = cached.SHA256 }, true);
        return new(file, await InspectWithBudgetAsync(file.FullName, progress, registration, token), false);
    }
}
