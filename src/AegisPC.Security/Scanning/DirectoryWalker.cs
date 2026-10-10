using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using Serilog;

namespace AegisPC.Security.Scanning
{
    /// <summary>
    /// Tarama türüne (Hızlı, Tam, Özel) göre hedef klasör ve sistem yollarını
    /// güvenle, takılmadan ve döngüye girmeden (Junction/ReparsePoint korumalı) gezen gezgin arayüzü.
    /// </summary>
    public interface IDirectoryWalker
    {
        /// <summary>
        /// Belirtilen dizini ve alt dizinlerini güvenle gezerek dosyaları kuyruklama delegesine iletir.
        /// </summary>
        Task EnumerateDirectorySafelyAsync(
            string dirPath,
            bool recursive,
            Func<string, Task> tryQueueFileAsync,
            CancellationToken cancellationToken,
            ManualResetEventSlim? pauseEvent = null);

        /// <summary>
        /// Belirtilen tarama türüne ait tüm hedef yolları (bellek, başlangıç, registry, disk sürücüleri) sırayla gezer.
        /// </summary>
        Task WalkDirectoriesForScanTypeAsync(
            ScanType scanType,
            string? customPath,
            Func<string, Task> tryQueueFileAsync,
            Action<string> reportProgress,
            CancellationToken cancellationToken,
            ManualResetEventSlim? pauseEvent = null);
    }

    /// <summary>
    /// Hızlı ve Tam tarama rotalarını, Windows kök dizini kurallarını ve
    /// bellek/kayıt defteri başlangıç noktalarını gezen sınıf.
    /// </summary>
    public partial class DirectoryWalker : IDirectoryWalker, IDirectoryCoverageProvider
    {
        public static readonly HashSet<string> ExcludedDirectoryNames = ScanFilterPolicy.ExcludedDirectoryNames;

        public async Task EnumerateDirectorySafelyAsync(
            string dirPath,
            bool recursive,
            Func<string, Task> tryQueueFileAsync,
            CancellationToken cancellationToken,
            ManualResetEventSlim? pauseEvent = null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var enqueue = tryQueueFileAsync;
            tryQueueFileAsync = file => DispatchInspectionFileAsync(file, enqueue, cancellationToken);
            if (string.IsNullOrWhiteSpace(dirPath)) return;
            if (!Directory.Exists(dirPath)) { _coverage.Value?.RecordDirectoryError(); return; }
            try
            {
                if ((File.GetAttributes(dirPath) & FileAttributes.ReparsePoint) != 0)
                { _coverage.Value?.RecordReparseSkip(); return; }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { _coverage.Value?.RecordDirectoryError(); Log.Debug(exception, "Directory attributes are unavailable."); return; }

            var dirQueue = new ConcurrentQueue<string>();
            var visitedDirs = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

            dirQueue.Enqueue(dirPath);
            visitedDirs.TryAdd(dirPath, 0);

            // Keep directory enumeration bounded on small CPUs. File scanning has a separate
            // worker pool; 4-16 walkers on a 1-2 core machine only add contention and memory use.
            int walkerCount = Math.Clamp(Environment.ProcessorCount, 1, 4);
            int activeWalkers = 0;

            var walkerTasks = Enumerable.Range(0, walkerCount).Select(async _ =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    pauseEvent?.Wait(cancellationToken);

                    if (!dirQueue.TryDequeue(out var currentDir))
                    {
                        if (Volatile.Read(ref activeWalkers) == 0 && dirQueue.IsEmpty)
                        {
                            break;
                        }
                        await Task.Delay(5, cancellationToken).ConfigureAwait(false);
                        if (Volatile.Read(ref activeWalkers) == 0 && dirQueue.IsEmpty)
                        {
                            break;
                        }
                        continue;
                    }

                    Interlocked.Increment(ref activeWalkers);
                    try
                    {
                        // 1. Dizin içindeki dosyaları kuyruğa ekle
                        foreach (var file in EnumerateDiscoveryEntries(currentDir, files: true))
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            pauseEvent?.Wait(cancellationToken);
                            await tryQueueFileAsync(file).ConfigureAwait(false);
                        }

                        // 2. Alt dizinleri kuyruğa ekle (Junction / ReparsePoint atlayarak sonsuz döngüyü engelle)
                        if (recursive)
                        {
                            foreach (var subDir in EnumerateDiscoveryEntries(currentDir, files: false))
                            {
                                if (cancellationToken.IsCancellationRequested) break;

                                try
                                {
                                    var dirInfo = new DirectoryInfo(subDir);
                                    if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                                    { _coverage.Value?.RecordReparseSkip(); continue; }

                                    // TAM KAPSAM: Windows kökünde de tüm alt dizinler taranır (WinSxS, Installer,
                                    // assembly, ProgramData dahil). Yalnızca ExcludedDirectoryNames listesi dışlanır.
                                    if (visitedDirs.TryAdd(subDir, 0))
                                    {
                                        dirQueue.Enqueue(subDir);
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _coverage.Value?.RecordDirectoryError();
                                    Log.Debug(ex, "Failed to inspect directory attribute or filter {SubDir}", subDir);
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                    {
                        _coverage.Value?.RecordDirectoryError();
                        Log.Debug(ex, "Failed to enumerate directory during walk");
                    } // Bir dizindeki erişim hatası diğer dizinleri durdurmaz
                    finally
                    {
                        Interlocked.Decrement(ref activeWalkers);
                    }
                }
            });

            try
            {
                await Task.WhenAll(walkerTasks).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
        }

        // Measure enumeration work without including file-queue backpressure or analysis.
        private static IEnumerable<string> EnumerateDiscoveryEntries(string path, bool files)
        {
            using var entries = (files ? Directory.EnumerateFiles(path) : Directory.EnumerateDirectories(path)).GetEnumerator();
            while (true)
            {
                bool available;
                string current = string.Empty;
                using (ScanStageMeasurements.Measure(ScanStageTiming.Discovery))
                {
                    available = entries.MoveNext();
                    if (available) current = entries.Current;
                }
                if (!available) yield break;
                yield return current;
            }
        }

        public async Task WalkDirectoriesForScanTypeAsync(
            ScanType scanType,
            string? customPath,
            Func<string, Task> tryQueueFileAsync,
            Action<string> reportProgress,
            CancellationToken cancellationToken,
            ManualResetEventSlim? pauseEvent = null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var enqueue = tryQueueFileAsync;
            tryQueueFileAsync = file => DispatchInspectionFileAsync(file, enqueue, cancellationToken);
            if (scanType == ScanType.Full)
            {
                reportProgress("Tam Tarama: Önce aktif program ve başlangıç dosyaları inceleniyor...");
                await (_quickPreflight ?? this).WalkDirectoriesForScanTypeAsync(ScanType.Quick, null, enqueue, reportProgress, cancellationToken, pauseEvent).ConfigureAwait(false);
                // Resolve actual volumes, not drive letters: folder mounts and GUID-only roots matter too.
                var volumes = await _volumeTargets.ResolveAsync(cancellationToken).ConfigureAwait(false);
                foreach (var limitation in volumes.Limitations) _coverage.Value?.RecordLimitation(limitation);
                var allDrives = volumes.VolumeRoots.Distinct(StringComparer.OrdinalIgnoreCase);

                foreach (var driveRoot in allDrives)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    reportProgress($"Disk taranıyor: {driveRoot}");
                    await EnumerateDirectorySafelyAsync(driveRoot, true, tryQueueFileAsync, cancellationToken, pauseEvent);
                }
            }
            else if (scanType == ScanType.Quick)
            {
                tryQueueFileAsync = file => DispatchImplicitInspectionFileAsync(file, enqueue, cancellationToken);
                var userTargets = await _scanTargets.ResolveAsync(cancellationToken).ConfigureAwait(false);
                foreach (var limitation in userTargets.Limitations) _coverage.Value?.RecordLimitation(limitation);
                // HIZLI TARAMA: AKTİF BELLEK SÜREÇLERİ, BAŞLANGIÇ & KRİTİK SİSTEM DİZİNLERİ
                reportProgress("Hızlı Tarama: Aktif program ve modül dosyaları inceleniyor (süreç belleği değil)...");
                try
                {
                    var activeProcesses = Process.GetProcesses();
                    try
                    {
                    foreach (var proc in activeProcesses)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        using (proc)
                        {
                        if (proc.Id <= 4) continue;
                        try
                        {
                            string? mainModule = proc.MainModule?.FileName;
                            if (!string.IsNullOrEmpty(mainModule))
                            {
                                await tryQueueFileAsync(mainModule);
                            }

                            foreach (ProcessModule mod in proc.Modules)
                            {
                                if (!string.IsNullOrEmpty(mod.FileName))
                                {
                                    await tryQueueFileAsync(mod.FileName);
                                }
                            }
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (ScanQueueDispatchException) { throw; }
                        catch (Exception ex)
                        {
                            _coverage.Value?.RecordProcessError();
                            Log.Debug(ex, "Failed to read modules for process {Pid}", proc.Id);
                        }
                        }
                    }
                    }
                    finally
                    {
                        // Cancellation may stop before every returned Process reaches its using block.
                        foreach (var process in activeProcesses) process.Dispose();
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (ScanQueueDispatchException) { throw; }
                catch (Exception ex)
                {
                    _coverage.Value?.RecordProcessError();
                    Log.Debug(ex, "Failed to iterate running processes during quick scan");
                }

                // Başlangıç ve Otomatik Çalıştırma Klasörleri
                reportProgress("Başlangıç ve Otomatik Çalıştırma Dizinleri taranıyor...");
                foreach (var target in userTargets.DirectoryTargets)
                    if (target.Kind == AegisPC.Core.Models.ScanDirectoryKind.UserStartup)
                        await EnumerateImplicitDirectoryAsync(target.Path, true, tryQueueFileAsync, cancellationToken, pauseEvent);
                    else if (target.Kind != AegisPC.Core.Models.ScanDirectoryKind.Documents)
                        await EnumerateRecentDirectoryAsync(target.Path, tryQueueFileAsync, cancellationToken, pauseEvent);
                await EnumerateImplicitDirectoryAsync(KnownPaths.CommonStartup, true, tryQueueFileAsync, cancellationToken, pauseEvent);

                // Windows Registry Autoruns (HKCU & HKLM Run anahtarları)
                try
                {
                    foreach (var profile in userTargets.Profiles)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (!profile.IsRegistryHiveLoaded)
                        { _coverage.Value?.RecordLimitation("UnloadedUserAutorunsNotInspected"); continue; }
                        using var userKey = Microsoft.Win32.Registry.Users.OpenSubKey(profile.OwnerSid + @"\Software\Microsoft\Windows\CurrentVersion\Run");
                        if (userKey == null) continue;
                        foreach (var valName in userKey.GetValueNames())
                        {
                            var rawVal = userKey.GetValue(valName)?.ToString();
                            if (!string.IsNullOrEmpty(rawVal))
                            {
                                var cleanPath = PathHelper.ExtractExecutablePath(rawVal);
                                if (IsEligibleImplicitTarget(cleanPath) && File.Exists(cleanPath)) await tryQueueFileAsync(cleanPath);
                            }
                        }
                    }

                    using var lmKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                    if (lmKey != null)
                    {
                        foreach (var valName in lmKey.GetValueNames())
                        {
                            var rawVal = lmKey.GetValue(valName)?.ToString();
                            if (!string.IsNullOrEmpty(rawVal))
                            {
                                var cleanPath = PathHelper.ExtractExecutablePath(rawVal);
                                if (IsEligibleImplicitTarget(cleanPath) && File.Exists(cleanPath)) await tryQueueFileAsync(cleanPath);
                            }
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (ScanQueueDispatchException) { throw; }
                catch (Exception ex)
                {
                    _coverage.Value?.RecordLimitation("RegistryAutorunsUnavailable");
                    Log.Debug(ex, "Failed to enumerate registry run keys during quick scan");
                }

                // Per-user downloads/desktop/temp were resolved above, not from SYSTEM's profile.
                await EnumerateRecentDirectoryAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), tryQueueFileAsync, cancellationToken, pauseEvent);
                _coverage.Value?.RecordLimitation("ServiceAndTaskPersistenceNotInspected");
            }
            else if (!string.IsNullOrEmpty(customPath))
            {
                cancellationToken.ThrowIfCancellationRequested();
                pauseEvent?.Wait(cancellationToken);
                if (File.Exists(customPath))
                {
                    if ((File.GetAttributes(customPath) & FileAttributes.ReparsePoint) != 0)
                        _coverage.Value?.RecordReparseSkip();
                    else await tryQueueFileAsync(Path.GetFullPath(customPath)).ConfigureAwait(false);
                }
                else await EnumerateDirectorySafelyAsync(customPath, true, tryQueueFileAsync, cancellationToken, pauseEvent);
            }
        }
    }
}
