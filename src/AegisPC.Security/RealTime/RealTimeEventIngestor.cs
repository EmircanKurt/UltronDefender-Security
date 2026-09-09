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
        /// Tampon doygunluğu nedeniyle düşürülen telemetri olay sayısı.
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
        /// Düşürülen olay tahmini sayısı.
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
    /// Güvenlik açısından kritik olayları asla düşürmeyen ve telemetri olaylarını sınırlandıran iki kanallı (Dual-Priority) olay toplayıcı.
    /// </summary>
    public class RealTimeEventIngestor : IRealTimeEventIngestor
    {
        private readonly Channel<NormalizedFileEvent> _criticalChannel;
        private readonly Channel<NormalizedFileEvent> _telemetryChannel;
        private readonly List<Task> _workerTasks = new();
        private readonly int _telemetryCapacity;
        private readonly ILogger<RealTimeEventIngestor>? _logger;

        private long _totalProducedEvents;
        private long _totalAcceptedEvents;
        private long _totalProcessedEvents;
        private long _totalDroppedEvents;
        private long _totalFailedEvents;
        private long _lastWarningLogged;

        public long TotalProducedEvents => Interlocked.Read(ref _totalProducedEvents);
        public long TotalAcceptedEvents => Interlocked.Read(ref _totalAcceptedEvents);
        public long TotalProcessedEvents => Interlocked.Read(ref _totalProcessedEvents);
        public long TotalDroppedEvents => Interlocked.Read(ref _totalDroppedEvents);
        public long TotalFailedEvents => Interlocked.Read(ref _totalFailedEvents);

        // Backward compatibility
        public long TotalEnqueuedEvents => TotalAcceptedEvents;
        public long DroppedEventsCount => TotalDroppedEvents;
        public int PendingEventsCount => _criticalChannel.Reader.Count + _telemetryChannel.Reader.Count;
        public int PendingCriticalCount => _criticalChannel.Reader.Count;
        public int PendingTelemetryCount => _telemetryChannel.Reader.Count;

        private static readonly HashSet<string> CriticalExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".msi", ".com", ".pif", ".vbe", ".wsf"
        };

        private static readonly HashSet<string> TelemetryExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".txt", ".bin", ".dat", ".iso", ".zip", ".rar", ".7z", ".jar"
        };

        private static readonly string[] IgnoredDirectoryMarkers = new[]
        {
            @"\.git\", @"\.vs\", @"\node_modules\", @"\obj\Debug\", @"\obj\Release\", @"\bin\Debug\", @"\bin\Release\", @"\.cache\"
        };

        public RealTimeEventIngestor(int channelCapacity = 2000, ILogger<RealTimeEventIngestor>? logger = null)
        {
            _telemetryCapacity = channelCapacity;
            _logger = logger;

            // Security-critical events channel: Unbounded, NEVER drops security-critical events
            _criticalChannel = Channel.CreateUnbounded<NormalizedFileEvent>(new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = false
            });

            // Informational telemetry channel: Bounded with Wait mode so TryWrite returns false when capacity is reached
            _telemetryChannel = Channel.CreateBounded<NormalizedFileEvent>(new BoundedChannelOptions(channelCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = false,
                SingleWriter = false
            });
        }

        public void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null)
        {
            if (string.IsNullOrWhiteSpace(path)) return;

            Interlocked.Increment(ref _totalProducedEvents);

            // Geliştirici ve IDE derleme gürültüsü filtresi (CPU spike ve buffer overflow önler)
            foreach (var marker in IgnoredDirectoryMarkers)
            {
                if (path.Contains(marker, StringComparison.OrdinalIgnoreCase)) return;
            }

            // ── SELF-PROTECTION: Kendi imza/veritabanı/log/config dizinlerindeki olayları yok say ──
            if (FileScannerService.IsSelfOwnedPath(path)) return;

            var ext = Path.GetExtension(path).ToLowerInvariant();
            bool isCritical = CriticalExtensions.Contains(ext);
            bool isTelemetry = TelemetryExtensions.Contains(ext);

            if (!isCritical && !isTelemetry) return;

            var normalizedEvent = new NormalizedFileEvent
            {
                EventType = type,
                FilePath = path,
                NormalizedPath = Path.GetFullPath(path),
                OldFilePath = oldPath,
                Extension = ext,
                Timestamp = DateTime.UtcNow
            };

            if (isCritical)
            {
                // Critical events are prioritized and never dropped
                _criticalChannel.Writer.TryWrite(normalizedEvent);
                Interlocked.Increment(ref _totalAcceptedEvents);
            }
            else
            {
                // Telemetry events: if queue is saturated, count exact drop and log warning
                if (_telemetryChannel.Writer.TryWrite(normalizedEvent))
                {
                    Interlocked.Increment(ref _totalAcceptedEvents);
                }
                else
                {
                    long dropped = Interlocked.Increment(ref _totalDroppedEvents);
                    if (dropped == 1 || dropped - _lastWarningLogged >= 100)
                    {
                        _lastWarningLogged = dropped;
                        _logger?.LogWarning("RealTimeEventIngestor telemetry queue is saturated ({Capacity} events). Dropped telemetry: {Dropped}", _telemetryCapacity, dropped);
                    }
                }
            }
        }

        public void StartWorkers(int workerCount, Func<NormalizedFileEvent, CancellationToken, Task> eventHandler, CancellationToken ct)
        {
            _workerTasks.Clear();
            for (int i = 0; i < workerCount; i++)
            {
                int workerId = i;
                _workerTasks.Add(Task.Run(() => ProcessEventLoopWorkerAsync(workerId, eventHandler, ct), ct));
            }
        }

        private async Task ProcessEventLoopWorkerAsync(int workerId, Func<NormalizedFileEvent, CancellationToken, Task> eventHandler, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                NormalizedFileEvent? evt = null;

                // 1. Highest Priority: drain all security-critical events
                if (_criticalChannel.Reader.TryRead(out var critEvt))
                {
                    evt = critEvt;
                }
                // 2. Secondary Priority: drain telemetry events
                else if (_telemetryChannel.Reader.TryRead(out var telemEvt))
                {
                    evt = telemEvt;
                }
                else
                {
                    // Await on either channel having data
                    var critTask = _criticalChannel.Reader.WaitToReadAsync(ct).AsTask();
                    var telemTask = _telemetryChannel.Reader.WaitToReadAsync(ct).AsTask();

                    var completed = await Task.WhenAny(critTask, telemTask);
                    if (ct.IsCancellationRequested) break;

                    try
                    {
                        if (await completed)
                        {
                            if (_criticalChannel.Reader.TryRead(out critEvt))
                            {
                                evt = critEvt;
                            }
                            else if (_telemetryChannel.Reader.TryRead(out telemEvt))
                            {
                                evt = telemEvt;
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }

                if (evt != null)
                {
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
                        _logger?.LogTrace(ex, "Worker {WorkerId} error handling event {Path}", workerId, evt.FilePath);
                    }
                }
            }
        }

        public void Stop()
        {
            _criticalChannel.Writer.TryComplete();
            _telemetryChannel.Writer.TryComplete();
            _workerTasks.Clear();
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
