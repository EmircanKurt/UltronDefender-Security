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

namespace AegisPC.Security.Safety
{
    /// <summary>
    /// Otomatik karantinalar için 30 günlük geri alma günlüğü ("cofa") ve karar zinciri yönetim servisi.
    /// Tek tıkla toplu geri alma ve şeffaf karar gerekçelendirmesi sağlayarak yanlış pozitif güvenini artırır.
    /// </summary>
    public class QuarantineUndoLogService : IQuarantineUndoLogService
    {
        private readonly IQuarantineService _quarantineService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger<QuarantineUndoLogService>? _logger;
        private readonly ConcurrentDictionary<int, QuarantineUndoEntry> _entries = new();
        private readonly string _storagePath;
        private readonly SemaphoreSlim _lock = new(1, 1);

        public static readonly TimeSpan DefaultRetentionWindow = TimeSpan.FromDays(30);

        public QuarantineUndoLogService(
            IQuarantineService quarantineService,
            IAuditLogService? auditLogService = null,
            ILogger<QuarantineUndoLogService>? logger = null,
            string? customStoragePath = null)
        {
            _quarantineService = quarantineService ?? throw new ArgumentNullException(nameof(quarantineService));
            _auditLogService = auditLogService;
            _logger = logger;

            string baseDir = customStoragePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "UltronDefender", "Quarantine");

            _storagePath = Path.Combine(baseDir, "quarantine_undo_log.json");
            LoadFromDisk();
        }

        private void LoadFromDisk()
        {
            try
            {
                if (File.Exists(_storagePath))
                {
                    string json = File.ReadAllText(_storagePath);
                    var list = JsonSerializer.Deserialize<List<QuarantineUndoEntry>>(json);
                    if (list != null)
                    {
                        foreach (var item in list)
                        {
                            _entries[item.QuarantineId] = item;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "QuarantineUndoLog diskten yüklenirken hata oluştu.");
            }
        }

        private async Task SaveToDiskAsync()
        {
            try
            {
                await _lock.WaitAsync();
                try
                {
                    string? dir = Path.GetDirectoryName(_storagePath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    // 30 günden eski kayıtları temizle (prune)
                    var cutoff = DateTime.UtcNow - DefaultRetentionWindow;
                    var activeList = _entries.Values
                        .Where(e => e.QuarantinedAt >= cutoff)
                        .ToList();

                    string json = JsonSerializer.Serialize(activeList, new JsonSerializerOptions { WriteIndented = true });
                    await File.WriteAllTextAsync(_storagePath, json);
                }
                finally
                {
                    _lock.Release();
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "QuarantineUndoLog diske yazılırken hata oluştu.");
            }
        }

        public async Task RecordQuarantineDecisionAsync(
            int quarantineId,
            string originalPath,
            int riskScore,
            string threatName,
            string decisionChain,
            CancellationToken ct = default)
        {
            var entry = new QuarantineUndoEntry
            {
                QuarantineId = quarantineId,
                OriginalPath = originalPath,
                FileName = Path.GetFileName(originalPath),
                ThreatName = threatName,
                RiskScore = riskScore,
                DecisionChain = decisionChain,
                QuarantinedAt = DateTime.UtcNow,
                IsRestored = false
            };

            _entries[quarantineId] = entry;
            _logger?.LogInformation("Geri Alma Günlüğüne kaydedildi: {Id} -> {Path} (Skor: {Score}, Tehdit: {Threat})",
                quarantineId, originalPath, riskScore, threatName);

            await SaveToDiskAsync();
        }

        public Task<List<QuarantineUndoEntry>> GetUndoLogEntriesAsync(
            TimeSpan? retentionWindow = null,
            CancellationToken ct = default)
        {
            var window = retentionWindow ?? DefaultRetentionWindow;
            var cutoff = DateTime.UtcNow - window;

            var result = _entries.Values
                .Where(e => e.QuarantinedAt >= cutoff && !e.IsRestored)
                .OrderByDescending(e => e.QuarantinedAt)
                .ToList();

            return Task.FromResult(result);
        }

        public Task<string?> GetDecisionChainAsync(int quarantineId, CancellationToken ct = default)
        {
            if (_entries.TryGetValue(quarantineId, out var entry))
            {
                return Task.FromResult<string?>(entry.DecisionChain);
            }
            return Task.FromResult<string?>(null);
        }

        public async Task<int> BulkRestoreAsync(IEnumerable<int> quarantineIds, CancellationToken ct = default)
        {
            int restoredCount = 0;

            foreach (var id in quarantineIds)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    bool restored = await _quarantineService.RestoreFileAsync(id, ct);
                    if (restored)
                    {
                        restoredCount++;
                        if (_entries.TryGetValue(id, out var entry))
                        {
                            entry.IsRestored = true;
                            entry.RestoredAt = DateTime.UtcNow;
                        }

                        _logger?.LogInformation("Toplu geri alma başarılı: ID {Id}", id);
                        if (_auditLogService != null)
                        {
                            _ = _auditLogService.LogActionAsync(
                                AegisPC.Core.Enums.AuditAction.FileRestored,
                                "QuarantineUndoLog",
                                entry?.FileName ?? id.ToString(),
                                entry?.OriginalPath,
                                $"Toplu geri alma günlüğü üzerinden dosya başarıyla geri yüklendi (ID: {id})",
                                AegisPC.Core.Enums.AuditResult.Success,
                                null,
                                ct);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Dosya geri yüklenirken hata oluştu (ID: {Id}).", id);
                }
            }

            if (restoredCount > 0)
            {
                await SaveToDiskAsync();
            }

            return restoredCount;
        }
    }
}
