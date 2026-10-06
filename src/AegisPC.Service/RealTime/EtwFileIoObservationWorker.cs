using System.Threading.Channels;
using AegisPC.Contracts.Protection;
using AegisPC.Contracts.Services;
using AegisPC.Security.UltronAI;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.RealTime;

/// <summary>
/// VM-gated post-operation file/thread/process observer. No native actions or firmware guarantees.
/// OS callbacks only capture bounded value records; correlation happens on the worker.
/// Existing processes without an observed creation/thread generation remain unattributed.
/// </summary>
public sealed class EtwFileIoObservationWorker(IBehaviorObservationSource observations,
    ISettingsService settings, ILogger<EtwFileIoObservationWorker> logger) : BackgroundService
{
    private sealed record Raw(int Kind, int Pid, int Tid, DateTimeOffset Time, ulong FileObject = 0, ulong FileKey = 0);
    private readonly Channel<Raw> _raw = Channel.CreateBounded<Raw>(new BoundedChannelOptions(2048)
    { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, AllowSynchronousContinuations = false });
    private readonly EtwActorCorrelationTable _actors = new();
    private long _dropped;
    private volatile bool _running;
    public bool IsObservationActive => _running;
    public long DroppedEvents => Interlocked.Read(ref _dropped);
    public long UnattributedWrites => _actors.UnattributedWrites;
    public long OsEventsLost { get; private set; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await settings.LoadAsync(stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
        catch (Exception ex) { logger.LogWarning("File-I/O pilot settings unavailable ({FailureType}); observer remains stopped.", ex.GetType().Name); return; }
        if (!settings.GetSetting("EnableExperimentalFileIoObservation", false))
        { logger.LogInformation("File-I/O observation remains gated until harmless Windows VM validation."); return; }
        string boot = WindowsBootObservationIdentity.Resolve(logger);
        TraceEventSession? session = null;
        Task? pump = null;
        try
        {
            session = new TraceEventSession("UltronFileIo-" + Guid.NewGuid().ToString("N")) { StopOnDispose = true, BufferSizeMB = 16 };
            // Avoid the library's implicit unbounded name/object maps; this pilot owns bounded actor maps.
            var kernel = new KernelTraceEventParser(session.Source, KernelTraceEventParser.ParserTrackingOptions.None);
            kernel.ProcessStart += e => Capture(new(1, e.ProcessID, 0, e.TimeStamp.ToUniversalTime()));
            kernel.ProcessStop += e => Capture(new(2, e.ProcessID, 0, e.TimeStamp.ToUniversalTime()));
            kernel.ThreadStart += e => Capture(new(3, e.ProcessID, e.ThreadID, e.TimeStamp.ToUniversalTime()));
            kernel.ThreadStop += e => Capture(new(4, e.ProcessID, e.ThreadID, e.TimeStamp.ToUniversalTime()));
            kernel.FileIOWrite += e => Capture(new(5, 0, e.ThreadID, e.TimeStamp.ToUniversalTime(), e.FileObject, e.FileKey));
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread |
                KernelTraceEventParser.Keywords.FileIO);
            _running = true;
            var live = session;
            pump = Task.Run(() => { try { live.Source.Process(); } finally { _running = false; _raw.Writer.TryComplete(); } }, CancellationToken.None);
            using var stop = stoppingToken.Register(() => session.Dispose());
            long seenDrops = 0;
            long sequence = 0;
            await foreach (var e in _raw.Reader.ReadAllAsync(stoppingToken))
            {
                long lost = session.EventsLost;
                if (seenDrops != DroppedEvents || lost != OsEventsLost)
                {
                    seenDrops = DroppedEvents; OsEventsLost = lost;
                    _actors.InvalidateContinuity();
                    observations.TryPublish(new($"io-gap-{++sequence}", "EtwContinuityGap", BehaviorObservationKind.CoverageGap,
                        null, DateTimeOffset.UtcNow, "File-I/O event continuity was lost; writer attribution is unknown."));
                }
                switch (e.Kind)
                {
                    case 1:
                        var actor = new BehaviorProcessIdentity(e.Pid, e.Time, boot);
                        _actors.ProcessStarted(actor);
                        observations.TryPublish(new($"io-process-{++sequence}", "ProcessStart", BehaviorObservationKind.ProcessStarted,
                            actor, e.Time, "Observed process creation; this is not malicious intent."));
                        break;
                    case 2: _actors.ProcessStopped(e.Pid, e.Time); break;
                    case 3: _actors.ThreadStarted(e.Tid, e.Pid, e.Time); break;
                    case 4: _actors.ThreadStopped(e.Tid, e.Time); break;
                    case 5:
                        var writer = _actors.ResolveWriter(e.Tid, e.Time);
                        observations.TryPublish(new($"io-write-{++sequence}", "FileWrite", BehaviorObservationKind.FileWritten,
                            writer, e.Time, $"Observed post-operation write; file object/key {e.FileObject:X}/{e.FileKey:X}; file content identity not verified.",
                            writer == null ? BehaviorAttribution.Unknown : BehaviorAttribution.EtwThreadGeneration));
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) { logger.LogWarning("File-I/O observation unavailable ({FailureType}); no actor containment is enabled.", ex.GetType().Name); }
        finally
        {
            _running = false;
            session?.Dispose();
            if (pump != null)
                try { await pump.WaitAsync(TimeSpan.FromSeconds(2)); }
                catch (Exception ex) { logger.LogWarning("File-I/O pump did not finish normally ({FailureType}).", ex.GetType().Name); }
        }
    }
    private void Capture(Raw value) { if (!_raw.Writer.TryWrite(value)) Interlocked.Increment(ref _dropped); }
}
