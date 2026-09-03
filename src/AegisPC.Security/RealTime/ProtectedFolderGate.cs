using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Korumalı klasörler ve izinli uygulamalar (Controlled Folder Access) yönetim kapısı arayüzü.
    /// </summary>
    public interface IProtectedFolderGate
    {
        /// <summary>
        /// Korumalı klasör yollarının salt-okunur listesi.
        /// </summary>
        IReadOnlyList<string> ProtectedDirectories { get; }

        /// <summary>
        /// Korumalı klasörlere yazma izni verilmiş güvenilir uygulamaların listesi.
        /// </summary>
        IReadOnlyList<AllowedRansomwareApplication> AllowedApplications { get; }

        /// <summary>
        /// Yeni bir klasörü fidye koruma kapsamına ekler.
        /// </summary>
        void AddProtectedDirectory(string path);

        /// <summary>
        /// Bir klasörü koruma kapsamından çıkarır.
        /// </summary>
        void RemoveProtectedDirectory(string path);

        /// <summary>
        /// Bir uygulamayı izinli beyaz listeye ekler.
        /// </summary>
        void AddAllowedApplication(string executablePath, string? appName = null);

        /// <summary>
        /// Bir uygulamayı izinli beyaz listeden çıkarır.
        /// </summary>
        void RemoveAllowedApplication(string executablePath);

        /// <summary>
        /// Belirtilen çalıştırılabilir dosyanın korumalı klasörlere erişim izni olup olmadığını denetler.
        /// </summary>
        bool IsApplicationAllowed(string executablePath);
    }

    /// <summary>
    /// Korumalı klasör listesini ve izin verilen uygulamalar beyaz listesini
    /// disk üzerinde kalıcı olarak yöneten ve erişim kontrolü sağlayan sınıf.
    /// </summary>
    public class ProtectedFolderGate : IProtectedFolderGate
    {
        private readonly List<string> _protectedDirs = new();
        private readonly List<AllowedRansomwareApplication> _allowedApps = new();
        private readonly string _storageFilePath;
        private readonly string _allowedAppsFilePath;
        private readonly ILogger? _logger;
        private readonly object _lock = new();

        private static readonly string[] DefaultAllowedExecutableNames = new[]
        {
            "explorer.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe",
            "code.exe", "devenv.exe", "notepad.exe", "notepad++.exe", "photoshop.exe",
            "acrobat.exe", "acrord32.exe", "onedrive.exe", "googledrivefs.exe", "dropbox.exe",
            "git.exe", "cmd.exe", "powershell.exe", "msedge.exe", "chrome.exe", "firefox.exe"
        };

        public IReadOnlyList<string> ProtectedDirectories
        {
            get { lock (_lock) return _protectedDirs.ToList(); }
        }

        public IReadOnlyList<AllowedRansomwareApplication> AllowedApplications
        {
            get { lock (_lock) return _allowedApps.ToList(); }
        }

        public ProtectedFolderGate(ILogger? logger = null)
        {
            _logger = logger;
            var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AegisPC");
            Directory.CreateDirectory(dataDir);
            _storageFilePath = Path.Combine(dataDir, "protected_folders.json");
            _allowedAppsFilePath = Path.Combine(dataDir, "allowed_ransomware_apps.json");

            LoadProtectedDirsFromDisk();
            LoadAllowedAppsFromDisk();
        }

        private void LoadProtectedDirsFromDisk()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_storageFilePath))
                    {
                        var json = File.ReadAllText(_storageFilePath);
                        var loaded = JsonSerializer.Deserialize<List<string>>(json);
                        if (loaded != null && loaded.Count > 0)
                        {
                            var existing = loaded.Where(Directory.Exists).ToList();
                            if (existing.Count > 0)
                            {
                                _protectedDirs.Clear();
                                _protectedDirs.AddRange(existing);
                                return;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to load protected folders from disk.");
                }

                // Initialize default user folders (Controlled Folder Access)
                var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var defaults = new[]
                {
                    Path.Combine(user, "Documents"),
                    Path.Combine(user, "Desktop"),
                    Path.Combine(user, "Pictures"),
                    Path.Combine(user, "Videos"),
                    Path.Combine(user, "Music"),
                    Path.Combine(user, "Downloads")
                }.Where(Directory.Exists);

                _protectedDirs.Clear();
                foreach (var d in defaults) _protectedDirs.Add(d);
                SaveProtectedDirsToDisk();
            }
        }

        private void SaveProtectedDirsToDisk()
        {
            try
            {
                var json = JsonSerializer.Serialize(_protectedDirs, new JsonSerializerOptions { WriteIndented = true });
                var tmp = _storageFilePath + ".tmp";
                File.WriteAllText(tmp, json);
                File.Move(tmp, _storageFilePath, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to save protected folders to disk.");
            }
        }

        private void LoadAllowedAppsFromDisk()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_allowedAppsFilePath))
                    {
                        var json = File.ReadAllText(_allowedAppsFilePath);
                        var loaded = JsonSerializer.Deserialize<List<AllowedRansomwareApplication>>(json);
                        if (loaded != null && loaded.Count > 0)
                        {
                            _allowedApps.Clear();
                            _allowedApps.AddRange(loaded);
                            return;
                        }
                    }
                }
                catch { }

                // Seed Default Whitelist Applications
                _allowedApps.Clear();
                foreach (var exe in DefaultAllowedExecutableNames)
                {
                    _allowedApps.Add(new AllowedRansomwareApplication
                    {
                        ExecutablePath = exe,
                        ApplicationName = Path.GetFileNameWithoutExtension(exe).ToUpperInvariant(),
                        Publisher = "System / Verified",
                        IsSigned = true,
                        IsSystemWhitelisted = true,
                        AddedAt = DateTime.UtcNow
                    });
                }
                SaveAllowedAppsToDisk();
            }
        }

        private void SaveAllowedAppsToDisk()
        {
            try
            {
                var json = JsonSerializer.Serialize(_allowedApps, new JsonSerializerOptions { WriteIndented = true });
                var tmp = _allowedAppsFilePath + ".tmp";
                File.WriteAllText(tmp, json);
                File.Move(tmp, _allowedAppsFilePath, overwrite: true);
            }
            catch { }
        }

        public void AddProtectedDirectory(string path)
        {
            lock (_lock)
            {
                if (Directory.Exists(path) && !_protectedDirs.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    _protectedDirs.Add(path);
                    SaveProtectedDirsToDisk();
                }
            }
        }

        public void RemoveProtectedDirectory(string path)
        {
            lock (_lock)
            {
                _protectedDirs.RemoveAll(p => p.Equals(path, StringComparison.OrdinalIgnoreCase));
                SaveProtectedDirsToDisk();
            }
        }

        public void AddAllowedApplication(string executablePath, string? appName = null)
        {
            lock (_lock)
            {
                if (!_allowedApps.Any(a => a.ExecutablePath.Equals(executablePath, StringComparison.OrdinalIgnoreCase)))
                {
                    _allowedApps.Add(new AllowedRansomwareApplication
                    {
                        ExecutablePath = executablePath,
                        ApplicationName = appName ?? Path.GetFileNameWithoutExtension(executablePath),
                        IsSigned = false,
                        IsSystemWhitelisted = false,
                        AddedAt = DateTime.UtcNow
                    });
                    SaveAllowedAppsToDisk();
                }
            }
        }

        public void RemoveAllowedApplication(string executablePath)
        {
            lock (_lock)
            {
                _allowedApps.RemoveAll(a => a.ExecutablePath.Equals(executablePath, StringComparison.OrdinalIgnoreCase));
                SaveAllowedAppsToDisk();
            }
        }

        public bool IsApplicationAllowed(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath)) return false;
            var fileName = Path.GetFileName(executablePath);

            // Self-Protection Guard: Ultron Defender binaries are always allowed
            if (string.Equals(fileName, "UltronDefender.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileName, "AegisPC.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileName, "UltronDefender", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(executablePath, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase) ||
                FileScannerService.IsSelfOwnedPath(executablePath))
            {
                return true;
            }

            lock (_lock)
            {
                return _allowedApps.Any(a => 
                    a.ExecutablePath.Equals(executablePath, StringComparison.OrdinalIgnoreCase) ||
                    a.ExecutablePath.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            }
        }
    }
}
