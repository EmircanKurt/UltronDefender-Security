using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
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
        private readonly Dictionary<string, CancellationTokenSource> _activeRecoveryTokens = new(StringComparer.OrdinalIgnoreCase);
        private long _unwatchedRecoveryRequests;
        private long _unwatchedRecoveryGeneration = -1;
        private long _watcherErrorCount;
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
            pathsToWatch.Add(downloads);

            // User Desktop
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (!string.IsNullOrWhiteSpace(desktop)) pathsToWatch.Add(desktop);

            // User Documents
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!string.IsNullOrWhiteSpace(documents)) pathsToWatch.Add(documents);

            // Droppers frequently arrive in Temp/AppData. Queue limits and duplicate merging,
            // rather than folder names, bound resource use without establishing a hiding place.
            foreach (var extra in new[] { Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) })
                if (!string.IsNullOrWhiteSpace(extra)) pathsToWatch.Add(extra);

            // A SYSTEM service does not inherit the interactive user's known folders.
            // Enumerate actual immediate profiles, not hard-coded usernames or trust-by-name rules.
            try
            {
                var targets = _scanTargets.ResolveAsync(_engineCts?.Token ?? CancellationToken.None).GetAwaiter().GetResult();
                foreach (var target in targets.DirectoryTargets)
                    pathsToWatch.Add(target.Path);
                if (!targets.IsComplete) _coverageDegraded = true;
            }
            catch (Exception ex) { _logger?.LogWarning(ex, "Registered profile watcher targets could not be resolved"); _coverageDegraded = true; }

            // Startup folders
            var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (!string.IsNullOrWhiteSpace(userStartup)) pathsToWatch.Add(userStartup);

            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            if (!string.IsNullOrWhiteSpace(commonStartup)) pathsToWatch.Add(commonStartup);

            // The service inventory owns media watchers by volume GUID + insertion generation.
            // Drive-letter-only watchers would duplicate the same physical file events.

            foreach (var path in pathsToWatch)
            {
                AttachWatcher(path);
            }
        }

        /// <summary>
        /// İzleme kapsamına yeni bir dinamik dizin yolu ekler. Kaynak başarıyla bağlanamazsa
        /// sağlık durumunu kısıtlı olarak bildirir; dosya erişimini önceden engellemez.
        /// </summary>
        /// <param name="path">İzlenecek dizinin tam yolu.</param>
        public void AddWatchDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;

            lock (_lock)
            {
                AttachWatcher(path);
                if (_isRunning) NotifyWatcherCoverage();
            }
        }

        /// <summary>
        /// Belirtilen dizin yolunu ve alt izleyicisini kapsamdan çıkarır, kaynaklarını serbest
        /// bırakır ve son etkin kök kaldırılmışsa koruma sağlığını kısıtlı olarak bildirir.
        /// </summary>
        /// <param name="path">Kapsamdan çıkarılacak dizin yolu.</param>
        public void RemoveWatchDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            path = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

            lock (_lock)
            {
                foreach (var recovery in _activeRecoveryTokens.Where(x => x.Key.StartsWith(path, StringComparison.OrdinalIgnoreCase)).ToArray())
                    recovery.Value.Cancel();
                _reconciliationRoots.RemoveWhere(x => x.StartsWith(path, StringComparison.OrdinalIgnoreCase));
                int previousCount = _watchers.Count;
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
                if (_isRunning && previousCount != _watchers.Count) NotifyWatcherCoverage();
            }
        }

        private void NotifyWatcherCoverage()
        {
            bool covered = !_coverageDegraded && _watchers.Count > 0;
            OnProtectionHealthChanged?.Invoke(covered, covered
                ? "Kullanıcı modu dosya geliş izleme etkin; yalnız listelenen dizinler kapsanıyor"
                : "Motor etkin; izleme kapsamı eksik veya henüz dizin seçilmedi");
        }

        /// <summary>
        /// Belirtilen klasör için FileSystemWatcher örneği bağlar ve hata kurtarma mekanizmasını kurar.
        /// </summary>
        /// <param name="path">İzlenecek klasör yolu.</param>
        private void AttachWatcher(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            if (!ImplicitLocalPathPolicy.IsEligible(path))
            {
                _coverageDegraded = true;
                _logger?.LogWarning("Implicit non-local or reparse watcher target was not attached; explicit local targeting is required.");
                return;
            }
            if (!Directory.Exists(path)) return;

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
                    InternalBufferSize = 65536
                };

                watcher.Created += (s, e) => EnqueueEvent(RealTimeEventType.Created, e.FullPath);
                watcher.Changed += (s, e) => EnqueueEvent(RealTimeEventType.Modified, e.FullPath);
                watcher.Deleted += (s, e) => EnqueueEvent(RealTimeEventType.Deleted, e.FullPath);
                watcher.Renamed += (s, e) => EnqueueEvent(RealTimeEventType.Renamed, e.FullPath, e.OldFullPath);
                watcher.Error += (s, e) => HandleWatcherError(watcher, path, e.GetException());

                _watchers.Add(watcher);
                _watchedLocationsList.Add(path);
                try
                {
                    // Register every callback before enabling the OS watcher; otherwise the
                    // initial arrivals and even an early overflow error can be lost silently.
                    if (_isRunning) watcher.EnableRaisingEvents = true;
                }
                catch
                {
                    _watchers.Remove(watcher);
                    _watchedLocationsList.Remove(path);
                    watcher.Dispose();
                    throw;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Could not initialize real-time watcher for {Path}; coverage remains partial", path);
                _coverageDegraded = true;
            }
        }

        private void HandleWatcherError(FileSystemWatcher watcher, string path, Exception? error)
        {
            _logger?.LogWarning(error, "FileSystemWatcher buffer overflow or I/O error on dynamic path {Path}.", path);
            lock (_lock)
            {
                // An error callback already in flight must not restart a removed or stopped root.
                if (!_isRunning || !_watchers.Contains(watcher)) return;
                _watcherErrorCount++;
                RequestReconciliation(path);
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.EnableRaisingEvents = true;
                }
                catch (Exception ex)
                {
                    _coverageDegraded = true;
                    _logger?.LogWarning(ex, "Could not restart file watcher {Path}; real-time coverage remains partial", path);
                    OnProtectionHealthChanged?.Invoke(false, "Dosya izleyicisi yeniden başlatılamadı; koruma kapsamı kısıtlı");
                }
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
                string? root = FindWatchedRoot(path);
                if (root == null)
                {
                    _coverageDegraded = true;
                    if (_unwatchedRecoveryGeneration != _engineGeneration)
                    {
                        _unwatchedRecoveryGeneration = _engineGeneration;
                        _unwatchedRecoveryRequests = 0;
                    }
                    long skipped = ++_unwatchedRecoveryRequests;
                    if (skipped == 1 || skipped % 100 == 0)
                        _logger?.LogWarning("Skipped {Count} recovery requests outside active watcher roots; coverage remains partial", skipped);
                    if (skipped == 1)
                        OnProtectionHealthChanged?.Invoke(false, "Olay kaybı izlendi; kapsam dışındaki dizin otomatik taranmadı");
                    return;
                }
                QueueDirectoryInspection(root, "Dosya geliş olayları kayboldu; sınırlandırılmış yeniden inceleme yapılıyor");
            }
        }

        private string? FindWatchedRoot(string path)
        {
            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException)
            {
                _logger?.LogWarning(ex, "Invalid path in watcher recovery request");
                return null;
            }

            // The trailing separator on registered roots prevents a sibling such as
            // C:\watched-extra from matching C:\watched. Exact root matches are valid too.
            return _watchedLocationsList
                .Where(root => fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                        root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(root => root.Length)
                .FirstOrDefault();
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
                // At most one outstanding recovery request per watcher; the roots set is bounded by coverage.
                if (_reconciliationRoots.Count >= Math.Max(1, _watchedLocationsList.Count) && !_reconciliationRoots.Contains(root))
                {
                    string? watchedRoot = FindWatchedRoot(root);
                    if (watchedRoot == null) { _coverageDegraded = true; return; }
                    _reconciliationRoots.RemoveWhere(x => x.StartsWith(watchedRoot, StringComparison.OrdinalIgnoreCase));
                    root = watchedRoot;
                }
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
            bool released = false;
            try
            {
                while (!token.IsCancellationRequested)
                {
                    string root;
                    lock (_lock)
                    {
                        if (generation != _engineGeneration) return;
                        if (_reconciliationRoots.Count == 0)
                        {
                            // Release under the same lock as queueing. A new request cannot be
                            // stranded between observing an empty queue and the old finally block.
                            _reconciliationRunning = false;
                            released = true;
                            return;
                        }
                        root = _reconciliationRoots.First();
                        _reconciliationRoots.Remove(root);
                    }
                    using var rootCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
                    lock (_lock)
                    {
                        if (FindWatchedRoot(root) == null) continue;
                        _activeRecoveryTokens[root] = rootCancellation;
                    }
                    try
                    {
                        await BoundedDirectoryInspection.WalkAsync(root, InspectBackgroundFileAsync,
                            reason => { lock (_lock) _coverageDegraded = true; _logger?.LogWarning("Recovery coverage limitation {Reason}", reason); }, rootCancellation.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (rootCancellation.IsCancellationRequested && !token.IsCancellationRequested) { }
                    finally
                    {
                        lock (_lock)
                            if (_activeRecoveryTokens.TryGetValue(root, out var current) && ReferenceEquals(current, rootCancellation))
                                _activeRecoveryTokens.Remove(root);
                    }
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception ex)
            {
                // The current root has already left the pending set. Even an empty
                // queue must retain the failure; an older generation cannot poison
                // the coverage of a replacement engine session.
                lock (_lock)
                    if (generation == _engineGeneration) _coverageDegraded = true;
                _logger?.LogError(ex, "Arrival reconciliation failed; coverage remains degraded");
            }
            finally
            {
                lock (_lock)
                {
                    if (!released && generation == _engineGeneration)
                    {
                        _reconciliationRunning = false;
                        if (token.IsCancellationRequested) _reconciliationRoots.Clear();
                        else if (_reconciliationRoots.Count > 0)
                        {
                            _coverageDegraded = true;
                            _reconciliationRunning = true;
                            _ = Task.Run(() => ReconcileArrivalsAsync(generation, token));
                        }
                    }
                }
            }
        }
    }
}

