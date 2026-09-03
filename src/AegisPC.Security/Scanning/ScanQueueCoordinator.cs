using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Tarama kuyruğu (BoundedChannel) üretici-tüketici koordinatörü arayüzü.
    /// </summary>
    public interface IScanQueueCoordinator
    {
        bool IsPaused { get; }
        ManualResetEventSlim PauseEvent { get; }
        void PauseScan();
        void ResumeScan();

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
    /// 8192 kapasiteli BoundedChannel kuyruğu, SSD/HDD donanım duyarlı paralel işçi havuzu,
    /// kooperatif CPU yönetimi ve duraklatma mekanizmasını yürüten koordinatör.
    /// </summary>
    public class ScanQueueCoordinator : IScanQueueCoordinator
    {
        private readonly ManualResetEventSlim _pauseEvent = new(true);

        public bool IsPaused => !_pauseEvent.IsSet;
        public ManualResetEventSlim PauseEvent => _pauseEvent;

        public void PauseScan() => _pauseEvent.Reset();
        public void ResumeScan() => _pauseEvent.Set();

        public async Task<(int TotalFiles, int ScannedFiles, int SkippedFiles)> ExecuteScanQueueAsync(
            string targetPath,
            ScanType scanType,
            Func<Func<string, Task>, Task> producerAction,
            Func<string, CancellationToken, Task<SecurityFinding?>> scanFileFunc,
            ConcurrentBag<SecurityFinding> findings,
            Action<string, int, int, int> reportProgressWithCounters,
            CancellationToken cancellationToken)
        {
            int totalFiles = 0;
            int scannedFiles = 0;
            int skippedFiles = 0;

            var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(8192)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleWriter = true,
                SingleReader = false
            });

            var queuedPaths = scanType != ScanType.Full ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) : null;

            async Task TryQueueFileAsync(string? filePath)
            {
                if (string.IsNullOrWhiteSpace(filePath) || cancellationToken.IsCancellationRequested) return;

                try
                {
                    if (queuedPaths == null || queuedPaths.Add(filePath))
                    {
                        int curTot = Interlocked.Increment(ref totalFiles);

                        string ext = Path.GetExtension(filePath);

                        // Fast-Path 1: Medya, doku, metin ve statik asset dosyalarını anında atla
                        if (!string.IsNullOrEmpty(ext) && ScanFilterPolicy.SafeMediaExtensions.Contains(ext))
                        {
                            int curScn = Interlocked.Increment(ref scannedFiles);
                            int curSkp = Volatile.Read(ref skippedFiles);
                            reportProgressWithCounters(filePath, curTot, curScn, curSkp);
                            return;
                        }

                        // Fast-Path 2: Oyun ve Mod Klasörü Koruması (Yalnızca yürütülebilir ikili dosyaları kuyruğa al)
                        bool isGame = PathHelper.IsGameOrRepackDirectory(filePath) || GameCrackClassifier.IsGameCrackOrEmulator(filePath);
                        if (isGame && (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" && ext != ".cmd" && ext != ".ps1"))
                        {
                            int curScn = Interlocked.Increment(ref scannedFiles);
                            int curSkp = Volatile.Read(ref skippedFiles);
                            reportProgressWithCounters(filePath, curTot, curScn, curSkp);
                            return;
                        }

                        // Fast-Path 3: Yürütülebilir / Script / Arşiv / İnceleme adaylarını paralel işçi kuyruğuna yaz
                        await channel.Writer.WriteAsync(filePath, cancellationToken);
                    }
                }
                catch { }
            }

            // Üretici Görevi
            var producerTask = Task.Run(async () =>
            {
                try
                {
                    await producerAction(TryQueueFileAsync);
                }
                finally
                {
                    channel.Writer.Complete();
                }
            }, cancellationToken);

            // Tüketici İşçileri: Donanım Duyarlı (SSD/NVMe vs HDD)
            bool isSsd = DiskHardwareHelper.IsSolidStateDrive(targetPath);
            int concurrency = isSsd
                ? Math.Clamp((int)Math.Ceiling(Environment.ProcessorCount * 0.75), 2, 8)
                : 2;

            var workerTasks = new List<Task>();

            for (int i = 0; i < concurrency; i++)
            {
                workerTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                        int fileProcessCounter = 0;

                        await foreach (var filePath in channel.Reader.ReadAllAsync(cancellationToken))
                        {
                            try
                            {
                                _pauseEvent.Wait(cancellationToken);
                                var finding = await scanFileFunc(filePath, cancellationToken);
                                if (finding != null)
                                {
                                    findings.Add(finding);
                                }
                            }
                            catch
                            {
                                Interlocked.Increment(ref skippedFiles);
                            }
                            finally
                            {
                                int currentScanned = Interlocked.Increment(ref scannedFiles);
                                fileProcessCounter++;

                                // Kooperatif CPU Nefes Alma: Her 50 dosyada bir Yield
                                if ((fileProcessCounter % 50) == 0)
                                {
                                    await Task.Yield();
                                }

                                // Periyodik hafif Gen0/Gen1 temizliği
                                if ((currentScanned % 1000) == 0)
                                {
                                    GC.Collect(0, GCCollectionMode.Optimized, false, false);
                                }

                                int curTot = Volatile.Read(ref totalFiles);
                                int curSkp = Volatile.Read(ref skippedFiles);
                                reportProgressWithCounters(filePath, curTot, currentScanned, curSkp);
                            }
                        }
                    }
                    catch (OperationCanceledException) { }
                }, cancellationToken));
            }

            workerTasks.Add(producerTask);
            await Task.WhenAll(workerTasks);

            return (Volatile.Read(ref totalFiles), Volatile.Read(ref scannedFiles), Volatile.Read(ref skippedFiles));
        }
    }
}
