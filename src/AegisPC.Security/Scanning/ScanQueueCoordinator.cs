using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
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
        private readonly IScanResourceManager? _injectedResourceManager;
        private readonly Action<ScanResourceProfile>? _profileChangedHandler;
        private readonly ILogger<ScanQueueCoordinator>? _logger;

        public bool IsPaused => !_pauseEvent.IsSet;
        public ManualResetEventSlim PauseEvent => _pauseEvent;

        public void PauseScan() => _pauseEvent.Reset();
        public void ResumeScan() => _pauseEvent.Set();

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

        public async Task<(int TotalFiles, int ScannedFiles, int SkippedFiles, int FailedFiles, int TimedOutFiles)> ExecuteScanQueueDetailedAsync(
            string targetPath,
            ScanType scanType,
            Func<Func<string, Task>, Task> producerAction,
            Func<string, CancellationToken, Task<FileScanDetailedResult>> scanFileFunc,
            ConcurrentBag<SecurityFinding> findings,
            Action<string, int, int, int, int, int> reportProgressWithCounters,
            CancellationToken cancellationToken)
        {
            int totalFiles = 0;
            int scannedFiles = 0;
            int skippedFiles = 0;
            int failedFiles = 0;
            int timedOutFiles = 0;

            var resourceManager = _injectedResourceManager ?? new AdaptiveScanResourceManager(targetPath);
            var activeProfile = resourceManager.ActiveProfile;

            int channelCapacity = activeProfile.ChannelCapacity;
            var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(channelCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleWriter = false,
                SingleReader = false
            });

            var queuedPaths = scanType != ScanType.Full ? new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase) : null;

            async Task TryQueueFileAsync(string? filePath)
            {
                if (string.IsNullOrWhiteSpace(filePath) || cancellationToken.IsCancellationRequested) return;

                try
                {
                    _pauseEvent.Wait(cancellationToken);

                    if (queuedPaths == null || queuedPaths.TryAdd(filePath, 0))
                    {
                        int curTot = Interlocked.Increment(ref totalFiles);

                        string ext = Path.GetExtension(filePath);

                        // Fast-Path 1: Medya ve statik asset dosyalarını anında atla
                        if (!string.IsNullOrEmpty(ext) && ScanFilterPolicy.SafeMediaExtensions.Contains(ext))
                        {
                            int curScn = Interlocked.Increment(ref scannedFiles);
                            int curSkp = Interlocked.Increment(ref skippedFiles);
                            // Raporlama kilidi baskısını azaltmak için periyodik güncelle
                            if (curTot % 20 == 0)
                            {
                                int curFail = Volatile.Read(ref failedFiles);
                                int curTout = Volatile.Read(ref timedOutFiles);
                                reportProgressWithCounters(filePath, curTot, curScn, curSkp, curFail, curTout);
                            }
                            return;
                        }

                        // Kural 27 gereğince: Oyun / repack klasör adı bazlı dosya atlama bypass'ı TAMAMEN KALDIRILDI.
                        // Her çalıştırılabilir ikili dosya, script ve arşiv adilce kuyruğa yazılır.
                        await channel.Writer.WriteAsync(filePath, cancellationToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    // Tarama iptal edildiğinde beklenen durum
                }
                catch (ChannelClosedException)
                {
                    // Kanal kapatıldığında / iptal edildiğinde beklenen durum
                }
                catch (Exception ex)
                {
                    _logger?.LogTrace(ex, "Dosya kuyruğa eklenirken hata: {Path}", filePath);
                }
            }

            // Üretici Görevi (Directory Walker)
            var producerTask = Task.Run(async () =>
            {
                try
                {
                    await producerAction(TryQueueFileAsync);
                }
                catch (OperationCanceledException) { }
                catch (ChannelClosedException) { }
                catch (Exception ex)
                {
                    _logger?.LogTrace(ex, "Producer task encountered an error.");
                }
                finally
                {
                    channel.Writer.TryComplete();
                }
            }, cancellationToken);

            // İptal durumunda kanal kapatma ve bekleyen işçileri anında uyandırma kaydı
            using var cancelRegistration = cancellationToken.Register(() =>
            {
                channel.Writer.TryComplete();
                _pauseEvent.Set();
            });

            // Tüketici İşçileri: Dinamik Concurrency Slot Gate ile yönetilir (Asgari 32 veya 4x çekirdek)
            int maxParallelWorkers = Math.Max(32, Math.Max(Environment.ProcessorCount * 4, activeProfile.Concurrency * 2));
            var workerTasks = new List<Task>();

            for (int i = 0; i < maxParallelWorkers; i++)
            {
                workerTasks.Add(Task.Run(async () =>
                {
                    int fileProcessCounter = 0;

                    try
                    {
                        while (!cancellationToken.IsCancellationRequested && await channel.Reader.WaitToReadAsync(cancellationToken))
                        {
                            // Duraklatma etkinse kuyruktan yeni dosya çekmeyi hemen dondur
                            _pauseEvent.Wait(cancellationToken);

                            if (!channel.Reader.TryRead(out var filePath))
                            {
                                continue;
                            }

                            if (cancellationToken.IsCancellationRequested) break;

                            // Adaptif Concurrency: Aktif profil kotası kadar işçinin eşzamanlı çalışmasına izin ver
                            await resourceManager.EnterWorkerSlotAsync(cancellationToken);

                            try
                            {
                                _pauseEvent.Wait(cancellationToken);

                                var detailedResult = await scanFileFunc(filePath, cancellationToken);
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
                                        break;

                                    case FileScanOutcome.Skipped:
                                        Interlocked.Increment(ref skippedFiles);
                                        break;
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
                                _logger?.LogTrace(ex, "Dosya taranırken hata: {Path}", filePath);
                                Interlocked.Increment(ref failedFiles);
                            }
                            finally
                            {
                                resourceManager.ExitWorkerSlot();

                                if (!cancellationToken.IsCancellationRequested)
                                {
                                    int currentScanned = Interlocked.Increment(ref scannedFiles);
                                    fileProcessCounter++;

                                    // Kooperatif gecikme ve bellek temizliği (Yalnızca profil pacing gerektiriyorsa)
                                    if (activeProfile.DelayBetweenFilesMs > 0 || (activeProfile.YieldFrequency > 0 && (fileProcessCounter % activeProfile.YieldFrequency == 0)))
                                    {
                                        await resourceManager.ApplyPacingAsync(fileProcessCounter, cancellationToken);
                                    }

                                    int curTot = Volatile.Read(ref totalFiles);
                                    int curSkp = Volatile.Read(ref skippedFiles);
                                    int curFail = Volatile.Read(ref failedFiles);
                                    int curTout = Volatile.Read(ref timedOutFiles);
                                    reportProgressWithCounters(filePath, curTot, currentScanned, curSkp, curFail, curTout);
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        _logger?.LogTrace(ex, "Worker task exited.");
                    }
                }, cancellationToken));
            }

            workerTasks.Add(producerTask);
            try
            {
                await Task.WhenAll(workerTasks);
            }
            catch (OperationCanceledException) { }

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
