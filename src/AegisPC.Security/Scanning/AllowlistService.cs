using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class AllowlistService : IAllowlistService
    {
        private readonly IHashService _hashService;
        private readonly ILogger<AllowlistService>? _logger;
        private readonly List<AllowlistEntry> _allowlist = new();
        private readonly ConcurrentDictionary<string, AllowlistEntry> _activeHashIndex = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, AllowlistEntry> _activePathIndex = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _storageFilePath;
        private readonly object _lock = new();

        public AllowlistService(IHashService hashService, ILogger<AllowlistService>? logger = null)
        {
            _hashService = hashService;
            _logger = logger;

            var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AegisPC");
            Directory.CreateDirectory(dataDir);
            _storageFilePath = Path.Combine(dataDir, "allowlist.json");

            LoadFromDisk();
        }

        private void LoadFromDisk()
        {
            lock (_lock)
            {
                try
                {
                    if (File.Exists(_storageFilePath))
                    {
                        var json = File.ReadAllText(_storageFilePath);
                        var items = JsonSerializer.Deserialize<List<AllowlistEntry>>(json);
                        if (items != null)
                        {
                            _allowlist.Clear();
                            _allowlist.AddRange(items);
                            _activeHashIndex.Clear();
                            _activePathIndex.Clear();
                            foreach (var item in _allowlist.Where(a => a.IsActive))
                            {
                                if (!string.IsNullOrEmpty(item.SHA256))
                                {
                                    _activeHashIndex[item.SHA256] = item;
                                }
                                if (!string.IsNullOrEmpty(item.FilePath))
                                {
                                    _activePathIndex[item.FilePath] = item;
                                    try
                                    {
                                        var norm = Path.GetFullPath(item.FilePath);
                                        _activePathIndex[norm] = item;
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to load allowlist from disk.");
                }
            }
        }

        private void SaveToDisk()
        {
            try
            {
                var json = JsonSerializer.Serialize(_allowlist, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_storageFilePath, json);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to save allowlist to disk.");
            }
        }

        public Task<bool> IsAllowlistedAsync(string sha256, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(sha256)) return Task.FromResult(false);
            return Task.FromResult(_activeHashIndex.ContainsKey(sha256));
        }

        public Task<bool> IsPathAllowlistedAsync(string filePath, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return Task.FromResult(false);
            if (_activePathIndex.ContainsKey(filePath)) return Task.FromResult(true);

            try
            {
                var norm = Path.GetFullPath(filePath);
                if (_activePathIndex.ContainsKey(norm)) return Task.FromResult(true);
            }
            catch { }

            return Task.FromResult(false);
        }

        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                entry.Id = _allowlist.Count > 0 ? _allowlist.Max(a => a.Id) + 1 : 1;
                entry.AddedAt = DateTime.UtcNow;
                entry.IsActive = true;
                _allowlist.Add(entry);
                if (!string.IsNullOrEmpty(entry.SHA256))
                {
                    _activeHashIndex[entry.SHA256] = entry;
                }
                if (!string.IsNullOrEmpty(entry.FilePath))
                {
                    _activePathIndex[entry.FilePath] = entry;
                    try
                    {
                        var norm = Path.GetFullPath(entry.FilePath);
                        _activePathIndex[norm] = entry;
                    }
                    catch { }
                }
                SaveToDisk();
            }
            _logger?.LogInformation("Added to allowlist: {Path} ({Hash})", entry.FilePath, entry.SHA256);
            return Task.CompletedTask;
        }

        public Task RemoveFromAllowlistAsync(int id, CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                var entry = _allowlist.FirstOrDefault(a => a.Id == id);
                if (entry != null)
                {
                    _allowlist.Remove(entry);
                    if (!string.IsNullOrEmpty(entry.SHA256))
                    {
                        _activeHashIndex.TryRemove(entry.SHA256, out _);
                    }
                    if (!string.IsNullOrEmpty(entry.FilePath))
                    {
                        _activePathIndex.TryRemove(entry.FilePath, out _);
                        try
                        {
                            var norm = Path.GetFullPath(entry.FilePath);
                            _activePathIndex.TryRemove(norm, out _);
                        }
                        catch { }
                    }
                    SaveToDisk();
                }
            }
            return Task.CompletedTask;
        }

        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken cancellationToken = default)
        {
            lock (_lock)
            {
                return Task.FromResult(_allowlist.Where(a => a.IsActive).ToList());
            }
        }

        public async Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken cancellationToken = default)
        {
            if (entry == null || !File.Exists(entry.FilePath)) return false;

            try
            {
                var currentHash = await _hashService.ComputeSha256Async(entry.FilePath, cancellationToken);
                return !string.Equals(entry.SHA256, currentHash, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to check hash for allowlist entry {Path}", entry.FilePath);
                return false;
            }
        }
    }
}
