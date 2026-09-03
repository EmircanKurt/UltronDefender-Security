using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;

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
    public class DirectoryWalker : IDirectoryWalker
    {
        public static readonly HashSet<string> ExcludedDirectoryNames = ScanFilterPolicy.ExcludedDirectoryNames;

        public async Task EnumerateDirectorySafelyAsync(
            string dirPath,
            bool recursive,
            Func<string, Task> tryQueueFileAsync,
            CancellationToken cancellationToken,
            ManualResetEventSlim? pauseEvent = null)
        {
            if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath) || cancellationToken.IsCancellationRequested) return;

            var dirQueue = new Queue<string>();
            dirQueue.Enqueue(dirPath);

            while (dirQueue.Count > 0 && !cancellationToken.IsCancellationRequested)
            {
                pauseEvent?.Wait(cancellationToken);
                string currentDir = dirQueue.Dequeue();

                try
                {
                    // 1. Dizin içindeki dosyaları kuyruğa ekle
                    foreach (var file in Directory.EnumerateFiles(currentDir))
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        pauseEvent?.Wait(cancellationToken);
                        await tryQueueFileAsync(file);
                    }

                    // 2. Alt dizinleri kuyruğa ekle (Junction / ReparsePoint atlayarak sonsuz döngüyü engelle)
                    if (recursive)
                    {
                        bool isWindowsRoot = currentDir.Equals(KnownPaths.WindowsDir, StringComparison.OrdinalIgnoreCase);

                        foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                        {
                            if (cancellationToken.IsCancellationRequested) break;

                            try
                            {
                                var dirInfo = new DirectoryInfo(subDir);
                                if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0) continue;

                                // Windows kök dizinindeyken yalnızca tehdit barındırabilecek kritik çalışma alanlarını kuyruğa ekle
                                if (isWindowsRoot)
                                {
                                    if (!dirInfo.Name.Equals("System32", StringComparison.OrdinalIgnoreCase) &&
                                        !dirInfo.Name.Equals("SysWOW64", StringComparison.OrdinalIgnoreCase) &&
                                        !dirInfo.Name.Equals("Temp", StringComparison.OrdinalIgnoreCase))
                                    {
                                        continue;
                                    }
                                }

                                if (ExcludedDirectoryNames.Contains(dirInfo.Name) ||
                                    dirInfo.Name.StartsWith("AegisLabSuite_", StringComparison.OrdinalIgnoreCase) ||
                                    dirInfo.Name.StartsWith("AegisPC_", StringComparison.OrdinalIgnoreCase)) continue;

                                dirQueue.Enqueue(subDir);
                            }
                            catch { }
                        }
                    }
                }
                catch { } // Bir dizindeki erişim hatası diğer dizinleri durdurmaz
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
            if (scanType == ScanType.Full)
            {
                // TAM DİSK TARAMASI: TÜM SABİT SÜRÜCÜLER TEK SEFERDE TEMİZCE TARANIR
                var allDrives = DriveInfo.GetDrives()
                    .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                    .Select(d => d.RootDirectory.FullName)
                    .ToList();

                foreach (var driveRoot in allDrives)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    reportProgress($"Disk taranıyor: {driveRoot}");
                    await EnumerateDirectorySafelyAsync(driveRoot, true, tryQueueFileAsync, cancellationToken, pauseEvent);
                }
            }
            else if (scanType == ScanType.Quick)
            {
                // HIZLI TARAMA: AKTİF BELLEK SÜREÇLERİ, BAŞLANGIÇ & KRİTİK SİSTEM DİZİNLERİ
                reportProgress("Hızlı Tarama: Aktif Bellek Süreçleri ve Modülleri taranıyor...");
                try
                {
                    var activeProcesses = Process.GetProcesses();
                    foreach (var proc in activeProcesses)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
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
                        catch { }
                    }
                }
                catch { }

                // Başlangıç ve Otomatik Çalıştırma Klasörleri
                reportProgress("Başlangıç ve Otomatik Çalıştırma Dizinleri taranıyor...");
                await EnumerateDirectorySafelyAsync(KnownPaths.UserStartup, true, tryQueueFileAsync, cancellationToken, pauseEvent);
                await EnumerateDirectorySafelyAsync(KnownPaths.CommonStartup, true, tryQueueFileAsync, cancellationToken, pauseEvent);

                // Windows Registry Autoruns (HKCU & HKLM Run anahtarları)
                try
                {
                    using var cuKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                    if (cuKey != null)
                    {
                        foreach (var valName in cuKey.GetValueNames())
                        {
                            var rawVal = cuKey.GetValue(valName)?.ToString();
                            if (!string.IsNullOrEmpty(rawVal))
                            {
                                var cleanPath = PathHelper.ExtractExecutablePath(rawVal);
                                if (File.Exists(cleanPath)) await tryQueueFileAsync(cleanPath);
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
                                if (File.Exists(cleanPath)) await tryQueueFileAsync(cleanPath);
                            }
                        }
                    }
                }
                catch { }

                // İndirilenler & Masaüstü (En yaygın indirme bulaşma noktaları)
                await EnumerateDirectorySafelyAsync(KnownPaths.Downloads, false, tryQueueFileAsync, cancellationToken, pauseEvent);
                await EnumerateDirectorySafelyAsync(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), false, tryQueueFileAsync, cancellationToken, pauseEvent);

                // Geçici Dizinler (%TEMP% ve Windows\Temp)
                await EnumerateDirectorySafelyAsync(KnownPaths.Temp, false, tryQueueFileAsync, cancellationToken, pauseEvent);
                await EnumerateDirectorySafelyAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), false, tryQueueFileAsync, cancellationToken, pauseEvent);

                // Sistem Sürücüleri ve System32
                reportProgress("Kritik Sistem Sürücüleri taranıyor...");
                await EnumerateDirectorySafelyAsync(Path.Combine(KnownPaths.System32, "drivers"), true, tryQueueFileAsync, cancellationToken, pauseEvent);
                await EnumerateDirectorySafelyAsync(KnownPaths.System32, false, tryQueueFileAsync, cancellationToken, pauseEvent);

                string sysWow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
                if (Directory.Exists(sysWow64))
                {
                    await EnumerateDirectorySafelyAsync(sysWow64, false, tryQueueFileAsync, cancellationToken, pauseEvent);
                }
            }
            else if (!string.IsNullOrEmpty(customPath) && Directory.Exists(customPath))
            {
                await EnumerateDirectorySafelyAsync(customPath, true, tryQueueFileAsync, cancellationToken, pauseEvent);
            }
        }
    }
}
