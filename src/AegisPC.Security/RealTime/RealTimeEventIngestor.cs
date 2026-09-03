using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı dosya sistemi olaylarını filtreleyen, normalize eden
    /// ve çok iş parçacıklı BoundedChannel kuyruğunda toplayan alıcı arayüzü.
    /// </summary>
    public interface IRealTimeEventIngestor : IDisposable
    {
        /// <summary>
        /// Ham dosya sistemi olayını filtreler ve kuyruğa ekler.
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
    /// FileSystemWatcher ve ETW olaylarını gürültüden arındırarak BoundedChannel kuyruğuna alan olay toplayıcı.
    /// </summary>
    public class RealTimeEventIngestor : IRealTimeEventIngestor
    {
        private readonly Channel<NormalizedFileEvent> _eventChannel;
        private readonly List<Task> _workerTasks = new();

        private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar", 
            ".iso", ".zip", ".rar", ".7z", ".vbe", ".wsf", ".cpl", ".msi", ".com", ".pif", ".txt", ".bin", ".dat"
        };

        private static readonly string[] IgnoredDirectoryMarkers = new[]
        {
            @"\.git\", @"\.vs\", @"\node_modules\", @"\obj\Debug\", @"\obj\Release\", @"\bin\Debug\", @"\bin\Release\", @"\.cache\"
        };

        public RealTimeEventIngestor(int channelCapacity = 2000)
        {
            _eventChannel = Channel.CreateBounded<NormalizedFileEvent>(new BoundedChannelOptions(channelCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,
                SingleWriter = false
            });
        }

        public void EnqueueEvent(RealTimeEventType type, string path, string? oldPath = null)
        {
            if (string.IsNullOrWhiteSpace(path)) return;

            // Geliştirici ve IDE derleme gürültüsü filtresi (CPU spike ve buffer overflow önler)
            foreach (var marker in IgnoredDirectoryMarkers)
            {
                if (path.Contains(marker, StringComparison.OrdinalIgnoreCase)) return;
            }

            // ── SELF-PROTECTION: Kendi imza/veritabanı/log/config dizinlerindeki olayları yok say ──
            if (FileScannerService.IsSelfOwnedPath(path)) return;

            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (!DangerousExtensions.Contains(ext)) return;

            var normalizedEvent = new NormalizedFileEvent
            {
                EventType = type,
                FilePath = path,
                NormalizedPath = Path.GetFullPath(path),
                OldFilePath = oldPath,
                Extension = ext,
                Timestamp = DateTime.UtcNow
            };

            _eventChannel.Writer.TryWrite(normalizedEvent);
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
            var reader = _eventChannel.Reader;
            while (!ct.IsCancellationRequested && await reader.WaitToReadAsync(ct))
            {
                while (reader.TryRead(out var evt))
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        await eventHandler(evt, ct);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        break;
                    }
                    catch
                    {
                        // Worker çökmesini engelle
                    }
                }
            }
        }

        public void Stop()
        {
            _workerTasks.Clear();
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
