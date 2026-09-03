using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
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

            // NOT: Temp, AppData ve ProgramData dizinleri kasıtlı olarak izleme dışı bırakıldı.
            // Bu dizinler saniyede yüzlerce dosya olayı üretir (tarayıcı cache, VS Code, Steam vb.)
            // ve FileSystemWatcher kernel buffer taşmasına, aşırı bellek tüketimine neden olur.
            // Bu dizinler yalnızca Quick/Full Scan sırasında taranır, real-time izleme gerekmez.

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
            catch { }

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
                        catch { }
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
                if (_watchedLocationsList.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    return;
                }

                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                    IncludeSubdirectories = true,
                    InternalBufferSize = 32768,
                    EnableRaisingEvents = _isRunning
                };

                watcher.Created += (s, e) => EnqueueEvent(RealTimeEventType.Created, e.FullPath);
                watcher.Changed += (s, e) => EnqueueEvent(RealTimeEventType.Modified, e.FullPath);
                watcher.Renamed += (s, e) => EnqueueEvent(RealTimeEventType.Renamed, e.FullPath, e.OldFullPath);
                watcher.Error += (s, e) =>
                {
                    _logger?.LogWarning(e.GetException(), "FileSystemWatcher buffer overflow or I/O error on dynamic path {Path}.", path);
                    OnProtectionHealthChanged?.Invoke(false, $"Dinamik Yol Arabellek Taşması: {path}");
                    try
                    {
                        watcher.EnableRaisingEvents = false;
                        watcher.EnableRaisingEvents = true;
                        OnProtectionHealthChanged?.Invoke(true, "Sağlıklı");
                    }
                    catch { }
                };

                _watchers.Add(watcher);
                _watchedLocationsList.Add(path);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Could not initialize real-time watcher for {Path}", path);
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
                    catch { }
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
            catch { }
        }
    }
}
