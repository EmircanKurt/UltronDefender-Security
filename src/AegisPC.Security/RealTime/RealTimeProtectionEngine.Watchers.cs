using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// RealTimeProtectionEngine sınıfının dosya izleme (FileSystemWatcher) ve
    /// USB / çıkarılabilir medya algılama mantığını barındıran partial parçası.
    /// </summary>
    public partial class RealTimeProtectionEngine
    {
        private readonly HashSet<string> _reconciliationRoots = new(StringComparer.OrdinalIgnoreCase);
        private bool _reconciliationRunning;
        /// <summary>
        /// Gerçek zamanlı olarak izlenen klasör yollarının salt-okunur listesi.
        /// </summary>
        public IReadOnlyList<string> WatchedLocations
        {
            get
            {
                lock (_lock) { return _watchedLocationsList.ToArray(); }
            }
        }

        /// <summary>
        /// Kullanıcının İndirilenler, Masaüstü, Belgeler, Başlangıç klasörleri ve
        /// takılı USB sürücüler için FileSystemWatcher örneklerini oluşturur ve yapılandırır.
        /// </summary>
        private void SetupFileSystemWatchers()
        {
            var pathsToWatch = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // User Downloads
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var downloads = Path.Combine(userProfile, "Downloads");
            if (Directory.Exists(downloads)) pathsToWatch.Add(downloads);

            // User Desktop
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (Directory.Exists(desktop)) pathsToWatch.Add(desktop);

            // User Documents
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (Directory.Exists(documents)) pathsToWatch.Add(documents);

            // Droppers frequently arrive in Temp/AppData. Queue limits and duplicate merging,
            // rather than folder names, bound resource use without establishing a hiding place.
            foreach (var extra in new[] { Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) })
                if (!string.IsNullOrWhiteSpace(extra) && Directory.Exists(extra)) pathsToWatch.Add(extra);

            // A SYSTEM service does not inherit the interactive user's known folders.
            // Enumerate actual immediate profiles, not hard-coded usernames or trust-by-name rules.
            if (System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem)
            {
                string profiles = Path.Combine(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\", "Users");
                try
                {
                    foreach (var profile in Directory.EnumerateDirectories(profiles))
                    {
                        if ((File.GetAttributes(profile) & FileAttributes.ReparsePoint) != 0) continue;
                        foreach (var relative in new[] { "Downloads", "Desktop", "Documents", @"AppData\Local", @"AppData\Roaming" })
                        {
                            string candidate = Path.Combine(profile, relative);
                            if (Directory.Exists(candidate)) pathsToWatch.Add(candidate);
                        }
                    }
                }
                catch (Exception ex) { _logger?.LogWarning(ex, "Could not enumerate interactive user profiles for real-time coverage"); _coverageDegraded = true; }
            }

            // Startup folders
            var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(userStartup)) pathsToWatch.Add(userStartup);

            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            if (Directory.Exists(commonStartup)) pathsToWatch.Add(commonStartup);

            // Removable / USB Drives
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType == DriveType.Removable && drive.IsReady)
                    {
                        pathsToWatch.Add(drive.RootDirectory.FullName);
                    }
                }
            }
            catch (Exception ex) { _logger?.LogWarning(ex, "Could not enumerate removable drives"); _coverageDegraded = true; }

            foreach (var path in pathsToWatch)
            {
                AttachWatcher(path);
            }
        }

        /// <summary>
        /// İzleme kapsamına yeni bir dinamik dizin yolu ekler.
        /// </summary>
        /// <param name="path">İzlenecek dizinin tam yolu.</param>
        public void AddWatchDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;

            lock (_lock)
            {
                AttachWatcher(path);
            }
        }

        /// <summary>
        /// Belirtilen dizin yolunu ve alt izleyicisini kapsamdan çıkarır ve kaynaklarını serbest bırakır.
        /// </summary>
        /// <param name="path">Kapsamdan çıkarılacak dizin yolu.</param>
        public void RemoveWatchDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            path = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            lock (_lock)
            {
                for (int i = _watchers.Count - 1; i >= 0; i--)
                {
                    if (string.Equals(_watchers[i].Path, path, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            _watchers[i].EnableRaisingEvents = false;
                            _watchers[i].Dispose();
                        }
                        catch (Exception ex) { _logger?.LogWarning(ex, "Could not remove file watcher {Path}", path); }
                        _watchers.RemoveAt(i);
                    }
                }
                _watchedLocationsList.RemoveAll(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase));
            }
        }

        /// <summary>
        /// Belirtilen klasör için FileSystemWatcher örneği bağlar ve hata kurtarma mekanizmasını kurar.
        /// </summary>
        /// <param name="path">İzlenecek klasör yolu.</param>
        private void AttachWatcher(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;

            try
            {
                path = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                {
                    _coverageDegraded = true;
                    _logger?.LogWarning("Real-time watcher root is a reparse point; explicit canonical targeting is required: {Path}", path);
                    return;
                }
                if (_watchedLocationsList.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    return;
                }

                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                    IncludeSubdirectories = true,
                    InternalBufferSize = 65536,
                    EnableRaisingEvents = _isRunning
                };

                watcher.Created += (s, e) => EnqueueEvent(RealTimeEventType.Created, e.FullPath);
                watcher.Changed += (s, e) => EnqueueEvent(RealTimeEventType.Modified, e.FullPath);
                watcher.Deleted += (s, e) => EnqueueEvent(RealTimeEventType.Deleted, e.FullPath);
                watcher.Renamed += (s, e) => EnqueueEvent(RealTimeEventType.Renamed, e.FullPath, e.OldFullPath);
                watcher.Error += (s, e) =>
                {
                    _logger?.LogWarning(e.GetException(), "FileSystemWatcher buffer overflow or I/O error on dynamic path {Path}.", path);
                    RequestReconciliation(path);
                    try
                    {
                        watcher.EnableRaisingEvents = false;
                        watcher.EnableRaisingEvents = true;
                    }
                    catch (Exception ex) { _logger?.LogWarning(ex, "Could not restart file watcher {Path}", path); }
                };

                _watchers.Add(watcher);
                _watchedLocationsList.Add(path);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Could not initialize real-time watcher for {Path}", path);
                _coverageDegraded = true;
            }
        }

        /// <summary>
        /// WMI Win32_VolumeChangeEvent sorgusuyla sisteme yeni takılan USB/çıkarılabilir sürücüleri
        /// dinamik olarak algılar ve otomatik olarak gerçek zamanlı koruma kapsamına alır.
        /// </summary>
        private void StartUsbArrivalListener()
        {
            try
            {
                var query = new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3");
                _usbArrivalWatcher = new ManagementEventWatcher(query);
                _usbArrivalWatcher.EventArrived += (s, e) =>
                {
                    try
                    {
                        var eventTypeObj = e.NewEvent.Properties["EventType"]?.Value;
                        int eventType = eventTypeObj != null ? Convert.ToInt32(eventTypeObj) : 0;
                        string? driveName = e.NewEvent.Properties["DriveName"]?.Value?.ToString();

                        if (!string.IsNullOrEmpty(driveName))
                        {
                            string drivePath = driveName.EndsWith('\\') ? driveName : driveName + "\\";
                            if (eventType == 2) // Arrival
                            {
                                _logger?.LogInformation("Yeni çıkarılabilir USB medya algılandı: {Drive}. Gerçek zamanlı koruma başlatılıyor...", drivePath);
                                AddWatchDirectory(drivePath);
                                OnNotificationRaised?.Invoke("💾 Yeni Medya Algılandı", $"{drivePath} çıkarılabilir sürücüsü gerçek zamanlı koruma altına alındı.", "Info");
                            }
                            else if (eventType == 3) // Removal
                            {
                                _logger?.LogInformation("Çıkarılabilir medya çıkarıldı: {Drive}", drivePath);
                                RemoveWatchDirectory(drivePath);
                            }
                        }
                    }
                    catch (Exception ex) { _logger?.LogWarning(ex, "Could not process removable-volume event"); }
                };
                _usbArrivalWatcher.Start();
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "USB dinamik WMI izleme başlatılamadı.");
            }
        }

        /// <summary>
        /// USB algılama WMI dinleyicisini durdurur ve nesnesini dispose eder.
        /// </summary>
        private void StopUsbArrivalListener()
        {
            try
            {
                if (_usbArrivalWatcher != null)
                {
                    _usbArrivalWatcher.Stop();
                    _usbArrivalWatcher.Dispose();
                    _usbArrivalWatcher = null;
                }
            }
            catch (Exception ex) { _logger?.LogWarning(ex, "Could not stop removable-volume listener"); }
        }

        private void RequestReconciliation(string path)
        {
            lock (_lock)
            {
                if (!_isRunning || _engineCts == null) return;
                string root = _watchedLocationsList.FirstOrDefault(location =>
                    path.StartsWith(location, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(path.TrimEnd('\\'), location.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    ?? Path.GetDirectoryName(path) ?? path;
                QueueDirectoryInspection(root, "Dosya geliş olayları kayboldu; sınırlandırılmış yeniden inceleme yapılıyor");
            }
        }

        private void RequestDirectoryInspection(string path)
        {
            lock (_lock)
            {
                if (!_isRunning || _engineCts == null) return;
                QueueDirectoryInspection(path, "Yeni taşınan klasörün içeriği arka planda inceleniyor");
            }
        }

        private void QueueDirectoryInspection(string root, string healthMessage)
        {
                if (_engineCts == null) return;
                _coverageDegraded = true;
                // At most one outstanding recovery request per watcher; the roots set is bounded by coverage.
                if (_reconciliationRoots.Count >= Math.Max(1, _watchedLocationsList.Count) && !_reconciliationRoots.Contains(root))
                    return;
                _reconciliationRoots.Add(root);
                OnProtectionHealthChanged?.Invoke(false, healthMessage);
                if (_reconciliationRunning) return;
                _reconciliationRunning = true;
                var token = _engineCts.Token;
                var generation = _engineGeneration;
                _ = Task.Run(() => ReconcileArrivalsAsync(generation, token));
        }

        private async Task ReconcileArrivalsAsync(long generation, CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    string root;
                    lock (_lock)
                    {
                        if (generation != _engineGeneration || _reconciliationRoots.Count == 0) return;
                        root = _reconciliationRoots.First();
                        _reconciliationRoots.Remove(root);
                    }
                    var pendingDirectories = new Stack<string>();
                    pendingDirectories.Push(root);
                    int inspected = 0;
                    const int maxRecoveryFiles = 50000;
                    while (pendingDirectories.Count > 0 && inspected < maxRecoveryFiles)
                    {
                        token.ThrowIfCancellationRequested();
                        string directory = pendingDirectories.Pop();
                        try
                        {
                            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) continue;
                            foreach (var file in Directory.EnumerateFiles(directory))
                            {
                                token.ThrowIfCancellationRequested();
                                if (++inspected > maxRecoveryFiles) break;
                                await HandleNormalizedEventAsync(new NormalizedFileEvent
                                {
                                    EventType = RealTimeEventType.Modified, FilePath = file,
                                    NormalizedPath = Path.GetFullPath(file), Extension = Path.GetExtension(file), Timestamp = DateTime.UtcNow
                                }, token);
                                // Recovery shares no unbounded managed queue and yields to foreground work.
                                await Task.Delay(5, token);
                            }
                            foreach (var child in Directory.EnumerateDirectories(directory))
                            {
                                if (pendingDirectories.Count >= 10000)
                                {
                                    _logger?.LogWarning("Arrival recovery directory budget reached under {Path}; coverage remains partial", root);
                                    break;
                                }
                                if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) pendingDirectories.Push(child);
                            }
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex) { _logger?.LogWarning(ex, "Arrival recovery could not inspect directory {Path}; coverage remains degraded", directory); }
                    }
                    _logger?.LogInformation("Arrival recovery inspected {Count} files under {Root}; budget {Budget}. Historical event loss remains recorded", inspected, root, maxRecoveryFiles);
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception ex) { _logger?.LogError(ex, "Arrival reconciliation failed; coverage remains degraded"); }
            finally
            {
                lock (_lock)
                {
                    if (generation == _engineGeneration)
                    {
                        _reconciliationRunning = false;
                        if (token.IsCancellationRequested) _reconciliationRoots.Clear();
                    }
                }
            }
        }
    }
}
