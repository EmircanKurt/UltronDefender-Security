using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Tarama kuyruğu (BoundedChannel) üretici-tüketici koordinatörü arayüzü.
    /// </summary>
    public interface IScanQueueCoordinator : IDisposable
    {
        bool IsPaused { get; }
        ManualResetEventSlim PauseEvent { get; }
        int ScannedFromCache { get; }
        int SkippedSignedClean { get; }
        int NewlyScanned { get; }
        /// <summary>Gets the number of workers currently analyzing a file.</summary>
        int ActiveWorkers => 0;
        /// <summary>Gets the current resource-policy worker limit.</summary>
        int EffectiveWorkerLimit => 0;
        /// <summary>Gets the number of files waiting for analysis or queue space.</summary>
        int PendingFiles => 0;
        /// <summary>Last owned pipeline's measured timing and per-volume throughput, including interrupted work.</summary>
        ScanMeasurementSummary? LastMeasurements => null;
        void ResetCounters();
        void PauseScan();
        void ResumeScan();

        Task<(int TotalFiles, int ScannedFiles, int SkippedFiles, int FailedFiles, int TimedOutFiles)> ExecuteScanQueueDetailedAsync(
            string targetPath,
            ScanType scanType,
            Func<Func<string, Task>, Task> producerAction,
            Func<string, CancellationToken, Task<FileScanDetailedResult>> scanFileFunc,
            ConcurrentBag<SecurityFinding> findings,
            Action<string, int, int, int, int, int> reportProgressWithCounters,
            CancellationToken cancellationToken);

        Task<(int TotalFiles, int ScannedFiles, int SkippedFiles)> ExecuteScanQueueAsync(
            string targetPath,
            ScanType scanType,
            Func<Func<string, Task>, Task> producerAction,
            Func<string, CancellationToken, Task<SecurityFinding?>> scanFileFunc,
            ConcurrentBag<SecurityFinding> findings,
            Action<string, int, int, int> reportProgressWithCounters,
            CancellationToken cancellationToken);
    }

    /// <summary>
    /// Adaptif kaynak yöneticisi (IScanResourceManager) ile entegre, dinamik işçi geçişini destekleyen,
    /// BoundedChannel kuyruğu ve kooperatif CPU/RAM yönetimi ile çalışan tarama koordinatörü.
    /// </summary>
    public class ScanQueueCoordinator : IScanQueueCoordinator
    {
        private readonly ManualResetEventSlim _pauseEvent = new(true);
        private readonly object _pauseLock = new();
        private volatile TaskCompletionSource<bool> _pauseTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly IScanResourceManager? _injectedResourceManager;
        private readonly Action<ScanResourceProfile>? _profileChangedHandler;
        private readonly ILogger<ScanQueueCoordinator>? _logger;

        private int _scannedFromCache;
        private int _skippedSignedClean;
        private int _newlyScanned;
        private int _activeWorkers;
        private int _pendingFiles;
        private IScanResourceManager? _activeResourceManager;

        public int ScannedFromCache => Volatile.Read(ref _scannedFromCache);
        public int SkippedSignedClean => Volatile.Read(ref _skippedSignedClean);
        public int NewlyScanned => Volatile.Read(ref _newlyScanned);
        /// <inheritdoc />
        public int ActiveWorkers => Volatile.Read(ref _activeWorkers);
        /// <inheritdoc />
        public int EffectiveWorkerLimit => Volatile.Read(ref _activeResourceManager)?.ActiveProfile.Concurrency ?? 0;
        /// <inheritdoc />
        public int PendingFiles => Math.Max(0, Volatile.Read(ref _pendingFiles));
        /// <inheritdoc />
        public ScanMeasurementSummary? LastMeasurements { get; private set; }

        public void ResetCounters()
        {
            Interlocked.Exchange(ref _scannedFromCache, 0);
            Interlocked.Exchange(ref _skippedSignedClean, 0);
            Interlocked.Exchange(ref _newlyScanned, 0);
            Interlocked.Exchange(ref _activeWorkers, 0);
            Interlocked.Exchange(ref _pendingFiles, 0);
        }

        public bool IsPaused => !_pauseEvent.IsSet;
        public ManualResetEventSlim PauseEvent => _pauseEvent;

        public void PauseScan()
        {
            _pauseEvent.Reset();
            lock (_pauseLock)
            {
                if (_pauseTcs.Task.IsCompleted)
                {
                    _pauseTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
            }
        }

        public void ResumeScan()
        {
            _pauseEvent.Set();
            lock (_pauseLock)
            {
                _pauseTcs.TrySetResult(true);
            }
        }

        private async Task WaitPauseAsync(CancellationToken cancellationToken)
        {
            if (!_pauseEvent.IsSet)
            {
                await _pauseTcs.Task.WaitAsync(cancellationToken);
            }
        }

        private static string _activeResourceSummary = string.Empty;

        /// <summary>
        /// Tarama kaynak kotası özeti (Örn: ⚖️ Dengeli (8 İş Parçacığı • 16 GB RAM'in ~8 GB'ı kullanılabilir)).
        /// Ekranda gösterilen ve motorda uygulanan tekil kaynak özeti.
        /// </summary>
        public static string ActiveResourceSummary
        {
            get
            {
                if (string.IsNullOrEmpty(_activeResourceSummary))
                {
                    _activeResourceSummary = ScanResourceProfile.CreateDefault().SummaryText;
                }
                return _activeResourceSummary;
            }
            set => _activeResourceSummary = value;
        }

        static ScanQueueCoordinator()
        {
            ScanHardwareProfile.ActiveSummaryProvider = () => ActiveResourceSummary;
        }

        public ScanQueueCoordinator(
            IScanResourceManager? resourceManager = null,
            ILogger<ScanQueueCoordinator>? logger = null)
        {
            _injectedResourceManager = resourceManager;
            _logger = logger;

            if (resourceManager != null)
            {
                ActiveResourceSummary = resourceManager.ActiveProfile.SummaryText;
                _profileChangedHandler = profile =>
                {
                    ActiveResourceSummary = profile.SummaryText;
                };
                resourceManager.ProfileChanged += _profileChangedHandler;
            }
        }

        public void Dispose()
        {
            if (_injectedResourceManager != null && _profileChangedHandler != null)
            {
                _injectedResourceManager.ProfileChanged -= _profileChangedHandler;
            }
            _pauseEvent.Dispose();
        }

        /// <summary>Processes every scoped file through the common scanner; fatal pipeline failures abort siblings and are rethrown after cleanup.</summary>
        public async Task<(int TotalFiles, int ScannedFiles, int SkippedFiles, int FailedFiles, int TimedOutFiles)> ExecuteScanQueueDetailedAsync(
            string targetPath,
            ScanType scanType,
            Func<Func<string, Task>, Task> producerAction,
            Func<string, CancellationToken, Task<FileScanDetailedResult>> scanFileFunc,
            ConcurrentBag<SecurityFinding> findings,
            Action<string, int, int, int, int, int> reportProgressWithCounters,
            CancellationToken cancellationToken)
        {
            ResetCounters();
            LastMeasurements = null;
            using var measurements = new ScanMeasurementRecorder();
            using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cancellationToken = abort.Token;
            ExceptionDispatchInfo? fatalFailure = null;
            int totalFiles = 0;
            int scannedFiles = 0;
            int skippedFiles = 0;
            int failedFiles = 0;
            int timedOutFiles = 0;

            var resourceManager = _injectedResourceManager ?? new AdaptiveScanResourceManager(targetPath);
            Volatile.Write(ref _activeResourceManager, resourceManager);
            try
            {
            resourceManager.ConfigureTarget(targetPath);
            if (scanType == ScanType.Full || string.IsNullOrWhiteSpace(targetPath)) resourceManager.ConfigureMultipleVolumes();
            resourceManager.RefreshProfile();
            var activeProfile = resourceManager.ActiveProfile;

            int channelCapacity = activeProfile.ChannelCapacity;
            var channel = new VolumeScanQueue<string>(channelCapacity,
                path => Path.GetPathRoot(Path.GetFullPath(path)) ?? "unknown",
                root => DiskHardwareHelper.IsSolidStateDrive(root) ? Math.Max(resourceManager.ActiveProfile.Concurrency, resourceManager.ActiveProfile.MaximumConcurrency) : 1);

            var queuedPaths = scanType != ScanType.Full ? new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase) : null;

            void Abort(Exception exception)
            {
                if (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                    exception = new InvalidOperationException("Scan pipeline cancelled without a requested scan cancellation.", exception);
                Interlocked.CompareExchange(ref fatalFailure, ExceptionDispatchInfo.Capture(exception), null);
                channel.Complete(exception);
                try { abort.Cancel(); }
                catch (AggregateException cancellationException)
                { _logger?.LogWarning(cancellationException, "A scan abort callback failed; the original pipeline failure is retained."); }
            }

            void NotifyProgress(string filePath, int total, int scanned, int skipped, int failed, int timedOut)
            {
                try { reportProgressWithCounters(filePath, total, scanned, skipped, failed, timedOut); }
                catch (Exception exception)
                { _logger?.LogWarning(exception, "Scan progress observer failed; file analysis continues."); }
            }

            async Task TryQueueFileAsync(string? filePath)
            {
                if (string.IsNullOrWhiteSpace(filePath)) return;
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    await WaitPauseAsync(cancellationToken);

                    if (queuedPaths == null || queuedPaths.TryAdd(filePath, 0))
                    {
                        Interlocked.Increment(ref totalFiles);
                        // Target scope is decided by the walker; only the common hash/content scanner can classify a file.
                        Interlocked.Increment(ref _pendingFiles);
                        try { await channel.WriteAsync(filePath, cancellationToken); }
                        catch (ChannelClosedException exception) when (cancellationToken.IsCancellationRequested)
                        {
                            // Closing the writer can win the race with the pending write's cancellation callback.
                            // Preserve a previously recorded fatal failure, but do not invent one for user cancellation.
                            Interlocked.Decrement(ref _pendingFiles);
                            throw new OperationCanceledException("Scan queue closed during cancellation.", exception, cancellationToken);
                        }
                        catch
                        {
                            Interlocked.Decrement(ref _pendingFiles);
                            throw;
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw; // Stop the producer too, including a walker using the caller's original token.
                }
                catch (Exception ex)
                {
                    Abort(ex);
                    _logger?.LogWarning(ex, "Queueing a scoped file failed: {Path}", filePath);
                    throw;
                }
            }

            // Üretici Görevi (Directory Walker)
            var producerTask = Task.Run(async () =>
            {
                try
                {
                    await producerAction(TryQueueFileAsync);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
                catch (Exception ex)
                {
                    Abort(ex);
                    _logger?.LogWarning(ex, "Scan producer failed; remaining work is aborted.");
                }
                finally
                {
                    channel.Complete();
                }
            }, cancellationToken);

            // İptal durumunda kanal kapatma ve bekleyen işçileri anında uyandırma kaydı
            using var cancelRegistration = cancellationToken.Register(() =>
            {
                channel.Complete();
                ResumeScan();
            });

            // Donanım üst sınırına kadar hazır bekleyen işçi havuzu oluşturulur.
            // Aktif çalışan işçi sayısı canlı izin bütçesi (EnterWorkerSlotAsync) ile dinamik olarak kontrol edilir.
            // Başlangıç işçi sayısına bağlı kalınmaz; mod VeryLow'dan High/Maximum'a geçtiğinde yeni işçiler anında devreye girer.
            int hardwareMaxWorkers = Math.Max(activeProfile.Concurrency, Math.Min(64, Environment.ProcessorCount * 4));
            var workerTasks = new List<Task>();

            for (int i = 0; i < hardwareMaxWorkers; i++)
            {
                workerTasks.Add(Task.Run(async () =>
                {
                    int fileProcessCounter = 0;

                    try
                    {
                        while (!cancellationToken.IsCancellationRequested)
                        {
                            // Duraklatma etkinse kuyruktan yeni dosya çekmeyi hemen asenkron dondur
                            await WaitPauseAsync(cancellationToken);

                            using var volumeLease = await channel.ReadAsync(cancellationToken);
                            if (volumeLease == null) break;
                            var filePath = volumeLease.Item;

                            if (cancellationToken.IsCancellationRequested)
                            {
                                Interlocked.Decrement(ref _pendingFiles);
                                break;
                            }

                            // Adaptif Concurrency: Aktif profil kotası kadar işçinin eşzamanlı çalışmasına izin ver
                            try
                            {
                                await RealtimeScanPriority.WaitAsync(cancellationToken);
                                await resourceManager.EnterWorkerSlotAsync(cancellationToken);
                            }
                            catch
                            {
                                Interlocked.Decrement(ref _pendingFiles);
                                throw;
                            }
                            Interlocked.Decrement(ref _pendingFiles);
                            Interlocked.Increment(ref _activeWorkers);

                            FileScanDetailedResult? detailedResult = null;
                            using var fileMeasurement = measurements.Begin(filePath, volumeLease.QueuedAt);
                            try
                            {
                                await WaitPauseAsync(cancellationToken);
                                await RealtimeScanPriority.WaitAsync(cancellationToken);

                                detailedResult = await scanFileFunc(filePath, cancellationToken);
                                switch (detailedResult.Outcome)
                                {
                                    case FileScanOutcome.Success:
                                        if (detailedResult.Finding != null)
                                        {
                                            findings.Add(detailedResult.Finding);
                                        }
                                        break;

                                    case FileScanOutcome.Timeout:
                                        Interlocked.Increment(ref timedOutFiles);
                                        break;

                                    case FileScanOutcome.Failed:
                                        Interlocked.Increment(ref failedFiles);
                                        if (detailedResult.Finding != null)
                                        {
                                            findings.Add(detailedResult.Finding);
                                        }
                                        break;

                                    case FileScanOutcome.Skipped:
                                        Interlocked.Increment(ref skippedFiles);
                                        break;
                                    default:
                                        throw new InvalidOperationException("File scanner returned an unsupported outcome.");
                                }
                            }
                            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                            {
                                break;
                            }
                            catch (OperationCanceledException)
                            {
                                // Tekil dosya zaman aşımı
                                Interlocked.Increment(ref timedOutFiles);
                            }
                            catch (Exception ex)
                            {
                                Interlocked.Increment(ref failedFiles);
                                Abort(ex);
                                _logger?.LogWarning(ex, "File-analysis worker failed: {Path}", filePath);
                                throw;
                            }
                            finally
                            {
                                Interlocked.Decrement(ref _activeWorkers);
                                resourceManager.ExitWorkerSlot();

                                if (!cancellationToken.IsCancellationRequested)
                                {
                                    int currentScanned = Interlocked.Increment(ref scannedFiles);
                                    resourceManager.ReportCompletedFiles(1);
                                    if (detailedResult != null)
                                    {
                                        if (detailedResult.IsFromCache)
                                        {
                                            Interlocked.Increment(ref _scannedFromCache);
                                        }
                                        else if (detailedResult.IsSignedClean)
                                        {
                                            Interlocked.Increment(ref _skippedSignedClean);
                                        }
                                        else
                                        {
                                            Interlocked.Increment(ref _newlyScanned);
                                        }
                                    }
                                    else
                                    {
                                        Interlocked.Increment(ref _newlyScanned);
                                    }

                                    fileProcessCounter++;

                                    // Kooperatif gecikme ve bellek temizliği:
                                    // Pacing başlangıç profilinden okunmaz; çalışma zamanındaki güncel profilden dinamik okunur.
                                    var currentProfile = resourceManager.ActiveProfile;
                                    if (currentProfile.DelayBetweenFilesMs > 0 || (currentProfile.YieldFrequency > 0 && (fileProcessCounter % currentProfile.YieldFrequency == 0)))
                                    {
                                        await resourceManager.ApplyPacingAsync(fileProcessCounter, cancellationToken);
                                    }

                                    int curTot = Volatile.Read(ref totalFiles);
                                    int curSkp = Volatile.Read(ref skippedFiles);
                                    int curFail = Volatile.Read(ref failedFiles);
                                    int curTout = Volatile.Read(ref timedOutFiles);
                                    NotifyProgress(filePath, curTot, currentScanned, curSkp, curFail, curTout);
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
                    catch (Exception ex)
                    {
                        Abort(ex);
                        _logger?.LogWarning(ex, "Scan worker exited with a fatal pipeline failure.");
                    }
                }, cancellationToken));
            }

            workerTasks.Add(producerTask);
            try
            {
                await Task.WhenAll(workerTasks);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
            }
            catch (Exception exception)
            {
                Interlocked.CompareExchange(ref fatalFailure, ExceptionDispatchInfo.Capture(exception), null);
            }
            finally
            {
                LastMeasurements = measurements.Snapshot();
                Volatile.Write(ref _activeResourceManager, null);
                Interlocked.Exchange(ref _pendingFiles, 0);
                // Yerel oluşturulan kaynak yöneticisi güvenle kapatılır
                if (_injectedResourceManager == null && resourceManager is IDisposable disp)
                {
                    try { disp.Dispose(); }
                    catch (Exception exception)
                    {
                        Interlocked.CompareExchange(ref fatalFailure, ExceptionDispatchInfo.Capture(exception), null);
                        _logger?.LogWarning(exception, "Scan resource cleanup failed.");
                    }
                }
            }

            fatalFailure?.Throw();

            return (
                Volatile.Read(ref totalFiles),
                Volatile.Read(ref scannedFiles),
                Volatile.Read(ref skippedFiles),
                Volatile.Read(ref failedFiles),
                Volatile.Read(ref timedOutFiles));
        }

        public async Task<(int TotalFiles, int ScannedFiles, int SkippedFiles)> ExecuteScanQueueAsync(
            string targetPath,
            ScanType scanType,
            Func<Func<string, Task>, Task> producerAction,
            Func<string, CancellationToken, Task<SecurityFinding?>> scanFileFunc,
            ConcurrentBag<SecurityFinding> findings,
            Action<string, int, int, int> reportProgressWithCounters,
            CancellationToken cancellationToken)
        {
            var (tot, scn, skp, _, _) = await ExecuteScanQueueDetailedAsync(
                targetPath,
                scanType,
                producerAction,
                async (path, ct) =>
                {
                    var finding = await scanFileFunc(path, ct);
                    return FileScanDetailedResult.CreateSuccess(path, finding, TimeSpan.Zero);
                },
                findings,
                (file, total, scanned, skipped, _, _) => reportProgressWithCounters(file, total, scanned, skipped),
                cancellationToken);

            return (tot, scn, skp);
        }
    }
}
