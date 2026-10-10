using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;
using AegisPC.Core.Models;
using AegisPC.Core.Helpers;
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

        /// <summary>Loads metadata in the default user store, or an isolated explicit store.
        /// An explicit store starts empty instead of seeding real personal folders; construction installs no enforcement.</summary>
        public ProtectedFolderGate(ILogger? logger = null, string? storageDirectory = null)
        {
            _logger = logger;
            var dataDir = storageDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AegisPC");
            Directory.CreateDirectory(dataDir);
            _storageFilePath = Path.Combine(dataDir, "protected_folders.json");
            _allowedAppsFilePath = Path.Combine(dataDir, "allowed_ransomware_apps.json");

            LoadProtectedDirsFromDisk(seedDefaults: storageDirectory == null);
            LoadAllowedAppsFromDisk();
        }

        private void LoadProtectedDirsFromDisk(bool seedDefaults)
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
                            // Load declarations as metadata only. The engine rejects unsafe roots before I/O,
                            // retaining a visible coverage gap instead of silently overwriting the user's list.
                            var declared = loaded.Where(path => !string.IsNullOrWhiteSpace(path) && Path.IsPathFullyQualified(path)).ToList();
                            if (declared.Count > 0)
                            {
                                _protectedDirs.Clear();
                                _protectedDirs.AddRange(declared);
                                return;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to load protected folders from disk.");
                }

                if (!seedDefaults) return;
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
                    .Where(p => ImplicitLocalPathPolicy.IsEligible(p) && Directory.Exists(p))
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
                if (ImplicitLocalPathPolicy.IsEligible(path) && Directory.Exists(path) && !_protectedDirs.Contains(path, StringComparer.OrdinalIgnoreCase))
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
        /// Records an explicit local executable path and its current SHA-256 identity.
        /// Unreadable/reparse targets are rejected; replacing a file invalidates this observation allowance.
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
                string? contentHash = ReadApplicationHash(canonicalPath);
                if (contentHash == null) return;
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
                            SHA256 = contentHash,
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
        /// Matches a user-listed canonical path AND its recorded content hash.
        /// Legacy path-only entries, changed content and product paths confer no trust.
        /// This observation check is not an identity-bound native write authorization.
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
                string? expectedHash;
                lock (_lock)
                {
                    expectedHash = _allowedApps.FirstOrDefault(application =>
                        !string.IsNullOrWhiteSpace(application.ExecutablePath) &&
                        Path.IsPathFullyQualified(application.ExecutablePath) &&
                        candidate.Equals(Path.GetFullPath(application.ExecutablePath),
                            StringComparison.OrdinalIgnoreCase))?.SHA256;
                }
                if (expectedHash == null || expectedHash.Length != 64 || !expectedHash.All(Uri.IsHexDigit)) return false;
                string? actualHash = ReadApplicationHash(candidate);
                return actualHash != null && actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Invalid allowed-application path {Path}.", executablePath);
                return false;
            }
        }

        private string? ReadApplicationHash(string path)
        {
            try
            {
                if (!ImplicitLocalPathPolicy.IsEligible(path)) return null;
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    64 * 1024, FileOptions.SequentialScan);
                return Convert.ToHexString(SHA256.HashData(stream));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                _logger?.LogWarning(ex, "Allowed application content identity could not be verified.");
                return null;
            }
        }
    }
}
