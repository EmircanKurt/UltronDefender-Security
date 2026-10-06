using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;

using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı dosya sistemi olaylarını filtreleyen, normalize eden
    /// ve çok iş parçacıklı BoundedChannel kuyruğunda toplayan alıcı arayüzü.
    /// </summary>
    public interface IRealTimeEventIngestor : IDisposable
    {
        /// <summary>
        /// Toplam üretilen (EnqueueEvent çağrılan) ham olay sayısı.
        /// </summary>
        long TotalProducedEvents { get; }

        /// <summary>
        /// Kanallara kabul edilen toplam olay sayısı.
        /// </summary>
        long TotalAcceptedEvents { get; }

        /// <summary>
        /// Başarıyla işlenen toplam olay sayısı.
        /// </summary>
        long TotalProcessedEvents { get; }

        /// <summary>
        /// Either priority's arrivals lost because a bounded queue was full or stopped.
        /// </summary>
        long TotalDroppedEvents { get; }

        /// <summary>
        /// İşleme sırasında hata alan olay sayısı.
        /// </summary>
        long TotalFailedEvents { get; }

        /// <summary>
        /// Geriye uyumluluk için toplam kabul edilen olay sayısı.
        /// </summary>
        long TotalEnqueuedEvents { get; }

        /// <summary>
        /// Exact managed-queue loss count; operating-system watcher losses are reported separately.
        /// </summary>
        long DroppedEventsCount { get; }

        /// <summary>
        /// Kuyruklarda işlenmeyi bekleyen anlık toplam olay sayısı.
        /// </summary>
        int PendingEventsCount { get; }

        /// <summary>
        /// Kritik kuyrukta bekleyen anlık olay sayısı.
        /// </summary>
        int PendingCriticalCount { get; }

        /// <summary>
        /// Telemetri kuyruğunda bekleyen anlık olay sayısı.
        /// </summary>
        int PendingTelemetryCount { get; }

        /// <summary>
        /// Ham dosya sistemi olayını filtreler ve uygun öncelik kanalına ekler.
        /// </summary>
        void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null);

        /// <summary>
        /// Olayları işleyecek arka plan worker havuzunu başlatır.
        /// </summary>
        void StartWorkers(int workerCount, Func<NormalizedFileEvent, CancellationToken, Task> eventHandler, CancellationToken ct);

        /// <summary>
        /// Kuyruğu ve worker görevlerini durdurur.
        /// </summary>
        void Stop();
    }

    /// <summary>
    /// Bounded dual-priority arrival queues. Overflow is visible and requests reconciliation;
    /// neither a managed queue nor FileSystemWatcher can promise lossless delivery.
    /// </summary>
    public class RealTimeEventIngestor : IRealTimeEventIngestor
    {
        private QueueSession _session;
        private readonly object _lifecycleLock = new();
        private CancellationTokenSource? _workerCts;
        private Task[] _workerTasks = Array.Empty<Task>();
        private bool _stopped;
        private bool _disposed;
        private readonly int _telemetryCapacity;
        private readonly ILogger<RealTimeEventIngestor>? _logger;

        private long _totalProducedEvents;
        private long _totalAcceptedEvents;
        private long _totalProcessedEvents;
        private long _totalDroppedEvents;
        private long _totalFailedEvents;
        private long _lastWarningLogged;
        private long _totalCoalescedEvents;

        public long TotalProducedEvents => Interlocked.Read(ref _totalProducedEvents);
        public long TotalAcceptedEvents => Interlocked.Read(ref _totalAcceptedEvents);
        public long TotalProcessedEvents => Interlocked.Read(ref _totalProcessedEvents);
        public long TotalDroppedEvents => Interlocked.Read(ref _totalDroppedEvents);
        public long TotalFailedEvents => Interlocked.Read(ref _totalFailedEvents);

        // Backward compatibility
        public long TotalEnqueuedEvents => TotalAcceptedEvents;
        public long DroppedEventsCount => TotalDroppedEvents;
        public int PendingEventsCount => PendingCriticalCount + PendingTelemetryCount;
        public int PendingCriticalCount => _session.Critical.Reader.Count;
        public int PendingTelemetryCount => _session.Telemetry.Reader.Count;

        /// <summary>Raised after event loss so the owner can inspect affected locations again.</summary>
        public event Action<string>? OnReconciliationRequired;

        /// <summary>Repeated path arrivals merged while that path is still queued; later writes are rescanned.</summary>
        public long TotalCoalescedEvents => Interlocked.Read(ref _totalCoalescedEvents);

        private static readonly HashSet<string> CriticalExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Queue priority only, never a trust or malware verdict. Archives may contain executable code.
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".msi", ".com", ".pif", ".vbe", ".wsf", ".jar", ".zip"
        };

        /// <summary>Creates independent bounded queues with a positive capacity per priority.</summary>
        public RealTimeEventIngestor(int channelCapacity = 2000, ILogger<RealTimeEventIngestor>? logger = null)
        {
            if (channelCapacity <= 0) throw new ArgumentOutOfRangeException(nameof(channelCapacity));
            _telemetryCapacity = channelCapacity;
            _logger = logger;
            _session = new QueueSession(channelCapacity);
        }

        /// <summary>Normalizes an arrival without trusting its name, directory or extension.</summary>
        public void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null)
        {
            if (string.IsNullOrWhiteSpace(path)) return;

            Interlocked.Increment(ref _totalProducedEvents);

            string normalizedPath;
            try { normalizedPath = Path.GetFullPath(path); }
            catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException)
            {
                Interlocked.Increment(ref _totalFailedEvents);
                _logger?.LogWarning(ex, "Invalid arrival path {Path}", path);
                return;
            }
            var ext = Path.GetExtension(normalizedPath).ToLowerInvariant();
            bool isCritical = CriticalExtensions.Contains(ext);

            var normalizedEvent = new NormalizedFileEvent
            {
                EventType = type,
                FilePath = path,
                NormalizedPath = normalizedPath,
                OldFilePath = oldPath,
                Extension = ext,
                Timestamp = DateTime.UtcNow
            };

            bool accepted;
            lock (_lifecycleLock)
            {
                if (!_stopped && !_disposed && _session.QueuedPaths.Contains(normalizedPath))
                {
                    Interlocked.Increment(ref _totalCoalescedEvents);
                    return;
                }
                accepted = !_stopped && !_disposed &&
                    (isCritical ? _session.Critical.Writer : _session.Telemetry.Writer).TryWrite(normalizedEvent);
                if (accepted)
                {
                    _session.QueuedPaths.Add(normalizedPath);
                    Interlocked.Increment(ref _totalAcceptedEvents);
                    _session.Available.Release();
                }
            }
            if (!accepted)
            {
                long dropped = Interlocked.Increment(ref _totalDroppedEvents);
                if (dropped == 1 || dropped - Interlocked.Read(ref _lastWarningLogged) >= 100)
                {
                    Interlocked.Exchange(ref _lastWarningLogged, dropped);
                    _logger?.LogWarning("Real-time arrival queue is saturated or stopped ({Capacity} per priority). Lost arrivals: {Dropped}", _telemetryCapacity, dropped);
                }
                RequestReconciliation(normalizedPath);
            }
        }

        /// <summary>Signals an inspection gap without allowing a subscriber failure to stop the arrival pump.</summary>
        private void RequestReconciliation(string normalizedPath)
        {
            try { OnReconciliationRequired?.Invoke(normalizedPath); }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Arrival reconciliation callback failed for {Path}", normalizedPath);
            }
        }

        /// <summary>Starts one worker generation; a stopped instance can be restarted safely.</summary>
        public void StartWorkers(int workerCount, Func<NormalizedFileEvent, CancellationToken, Task> eventHandler, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(eventHandler);
            if (workerCount <= 0) throw new ArgumentOutOfRangeException(nameof(workerCount));
            lock (_lifecycleLock)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_workerCts != null) throw new InvalidOperationException("Arrival workers have already started.");
                if (_stopped) _session = new QueueSession(_telemetryCapacity);
                _stopped = false;
                _workerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var session = _session;
                var workerToken = _workerCts.Token;
                _workerTasks = new Task[workerCount];
                for (int i = 0; i < workerCount; i++)
                {
                    int workerId = i;
                    _workerTasks[i] = Task.Run(() => ProcessEventLoopWorkerAsync(session, workerId, eventHandler, workerToken));
                }
            }
        }

        private async Task ProcessEventLoopWorkerAsync(QueueSession session, int workerId, Func<NormalizedFileEvent, CancellationToken, Task> eventHandler, CancellationToken ct)
        {
            int criticalBurst = 0;
            while (!ct.IsCancellationRequested)
            {
                try { await session.Available.WaitAsync(ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                NormalizedFileEvent? evt = null;
                // Fairness prevents renamed/disguised payloads in the normal queue starving forever.
                if (criticalBurst >= 8 && session.Telemetry.Reader.TryRead(out evt))
                {
                    criticalBurst = 0;
                }
                else if (session.Critical.Reader.TryRead(out evt))
                {
                    criticalBurst++;
                }
                else if (session.Telemetry.Reader.TryRead(out evt))
                {
                    criticalBurst = 0;
                }

                if (evt != null)
                {
                    lock (_lifecycleLock) session.QueuedPaths.Remove(evt.NormalizedPath);
                    try
                    {
                        await eventHandler(evt, ct);
                        Interlocked.Increment(ref _totalProcessedEvents);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref _totalFailedEvents);
                        _logger?.LogWarning(ex, "Worker {WorkerId} error handling event {Path}", workerId, evt.FilePath);
                        RequestReconciliation(evt.NormalizedPath);
                    }
                }
            }
        }

        /// <summary>Cancels this worker generation and closes its queues without busy spinning.</summary>
        public void Stop()
        {
            CancellationTokenSource? workers;
            Task[] tasks;
            QueueSession session;
            lock (_lifecycleLock)
            {
                if (_stopped) return;
                _stopped = true;
                session = _session;
                session.Critical.Writer.TryComplete();
                session.Telemetry.Writer.TryComplete();
                workers = _workerCts;
                _workerCts = null;
                tasks = _workerTasks;
                _workerTasks = Array.Empty<Task>();
            }
            workers?.Cancel();
            _ = Task.WhenAll(tasks).ContinueWith(completed =>
            {
                if (completed.IsFaulted) _logger?.LogError(completed.Exception, "Arrival worker generation failed during shutdown");
                workers?.Dispose();
                session.Available.Dispose();
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }

        /// <summary>Stops the ingestor permanently; later worker starts are rejected.</summary>
        public void Dispose()
        {
            lock (_lifecycleLock) _disposed = true;
            Stop();
        }

        private sealed class QueueSession
        {
            internal readonly Channel<NormalizedFileEvent> Critical;
            internal readonly Channel<NormalizedFileEvent> Telemetry;
            internal readonly SemaphoreSlim Available = new(0);
            internal readonly HashSet<string> QueuedPaths = new(StringComparer.OrdinalIgnoreCase);
            internal QueueSession(int capacity)
            {
                var options = new BoundedChannelOptions(capacity) { FullMode = BoundedChannelFullMode.Wait };
                Critical = Channel.CreateBounded<NormalizedFileEvent>(options);
                Telemetry = Channel.CreateBounded<NormalizedFileEvent>(options);
            }
        }
    }
}
