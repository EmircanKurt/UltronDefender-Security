using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AegisPC.Core.Models;
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
        /// Belirtilen dosya veya dizin yolunun korumalı klasörlerden birinin altında olup olmadığını denetler.
        /// </summary>
        bool IsPathInsideProtectedDirectory(string path);

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
                var candidateFolders = new List<string>
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
                    Path.Combine(user, "Documents"),
                    Path.Combine(user, "Desktop"),
                    Path.Combine(user, "Pictures"),
                    Path.Combine(user, "Videos"),
                    Path.Combine(user, "Music"),
                    Path.Combine(user, "Downloads")
                };

                var defaults = candidateFolders
                    .Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p))
                    .Distinct(StringComparer.OrdinalIgnoreCase);

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
                        if (loaded != null)
                        {
                            _allowedApps.Clear();
                            // Legacy filename-only entries were never identity-bound and are not allowances.
                            _allowedApps.AddRange(loaded.Where(a =>
                                !string.IsNullOrWhiteSpace(a.ExecutablePath) &&
                                Path.IsPathFullyQualified(a.ExecutablePath)));
                            return;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to load allowed applications from disk.");
                }

                // No implicit filename-based trust is seeded into the allowlist.
                _allowedApps.Clear();
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
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to save allowed applications to disk.");
            }
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

        /// <summary>
        /// Adds an explicit, fully qualified executable path to the protected-folder allowlist.
        /// Relative names are rejected because any program can copy a trusted display name.
        /// </summary>
        public void AddAllowedApplication(string executablePath, string? appName = null)
        {
            if (string.IsNullOrWhiteSpace(executablePath) ||
                !Path.IsPathFullyQualified(executablePath))
            {
                _logger?.LogWarning("Rejected non-absolute allowed-application path {Path}.", executablePath);
                return;
            }

            try
            {
                string canonicalPath = Path.GetFullPath(executablePath);
                lock (_lock)
                {
                    if (!_allowedApps.Any(a =>
                        Path.IsPathFullyQualified(a.ExecutablePath) &&
                        Path.GetFullPath(a.ExecutablePath).Equals(canonicalPath,
                            StringComparison.OrdinalIgnoreCase)))
                    {
                        _allowedApps.Add(new AllowedRansomwareApplication
                        {
                            ExecutablePath = canonicalPath,
                            ApplicationName = appName ?? Path.GetFileNameWithoutExtension(canonicalPath),
                            IsSigned = false,
                            IsSystemWhitelisted = false,
                            AddedAt = DateTime.UtcNow
                        });
                        SaveAllowedAppsToDisk();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to add allowed-application path {Path}.", executablePath);
            }
        }

        /// <summary>
        /// Removes a previously allowed absolute path, including equivalent normalized spellings.
        /// Invalid or relative paths cannot remove an unrelated application entry.
        /// </summary>
        public void RemoveAllowedApplication(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath) ||
                !Path.IsPathFullyQualified(executablePath)) return;

            try
            {
                string canonicalPath = Path.GetFullPath(executablePath);
                lock (_lock)
                {
                    int removed = _allowedApps.RemoveAll(a =>
                        Path.IsPathFullyQualified(a.ExecutablePath) &&
                        Path.GetFullPath(a.ExecutablePath).Equals(canonicalPath,
                            StringComparison.OrdinalIgnoreCase));
                    if (removed > 0) SaveAllowedAppsToDisk();
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to remove allowed-application path {Path}.", executablePath);
            }
        }

        /// <summary>
        /// Checks canonical directory membership at a path-segment boundary, rejecting sibling prefixes.
        /// Invalid paths are treated as outside the protected set and logged.
        /// </summary>
        public bool IsPathInsideProtectedDirectory(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                string candidate = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
                lock (_lock)
                {
                    return _protectedDirs.Any(directory =>
                    {
                        string root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
                        return candidate.Equals(root, StringComparison.OrdinalIgnoreCase) ||
                               candidate.StartsWith(root + Path.DirectorySeparatorChar,
                                   StringComparison.OrdinalIgnoreCase);
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Invalid protected-folder path {Path}.", path);
                return false;
            }
        }

        /// <summary>
        /// Allows only this process's exact executable or a user-listed canonical absolute path.
        /// Product-directory membership, display names, and relative entries confer no trust.
        /// </summary>
        public bool IsApplicationAllowed(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath) ||
                !Path.IsPathFullyQualified(executablePath))
            {
                return false;
            }

            try
            {
                string candidate = Path.GetFullPath(executablePath);
                string? currentExecutable = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(currentExecutable) &&
                    candidate.Equals(Path.GetFullPath(currentExecutable), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                lock (_lock)
                {
                    return _allowedApps.Any(application =>
                        !string.IsNullOrWhiteSpace(application.ExecutablePath) &&
                        Path.IsPathFullyQualified(application.ExecutablePath) &&
                        candidate.Equals(Path.GetFullPath(application.ExecutablePath),
                            StringComparison.OrdinalIgnoreCase));
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Invalid allowed-application path {Path}.", executablePath);
                return false;
            }
        }
    }
}
