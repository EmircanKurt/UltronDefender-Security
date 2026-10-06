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

namespace AegisPC.Security.Reputation
{
    /// <summary>
    /// Yerel İtibar Hizmeti: Dosyaların makinede ilk görülme tarihi, türediği üst süreç ve güvenlik geçmişini takip eder.
    /// "Bu dosya 6 aydır sorunsuz" sinyali risk skoruna -10 katkı sağlar.
    /// </summary>
    public class LocalReputationService : ILocalReputationService
    {
        private readonly ILogger<LocalReputationService>? _logger;
        private readonly ConcurrentDictionary<string, LocalReputationRecord> _records = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _storagePath;
        private readonly SemaphoreSlim _lock = new(1, 1);

        public const double CleanAgeDaysThreshold = 180.0;
        public const int CleanAgeDiscountScore = -10;

        public LocalReputationService(
            ILogger<LocalReputationService>? logger = null,
            string? customStoragePath = null)
        {
            _logger = logger;
            string baseDir = customStoragePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "UltronDefender", "Reputation");

            _storagePath = Path.Combine(baseDir, "local_reputation.json");
            LoadFromDisk();
        }

        private void LoadFromDisk()
        {
            try
            {
                if (File.Exists(_storagePath))
                {
                    string json = File.ReadAllText(_storagePath);
                    var list = JsonSerializer.Deserialize<List<LocalReputationRecord>>(json);
                    if (list != null)
                    {
                        foreach (var record in list)
                        {
                            if (!string.IsNullOrWhiteSpace(record.SHA256))
                            {
                                _records[record.SHA256] = record;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "LocalReputation diskten yüklenirken hata oluştu.");
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

                    var list = _records.Values.ToList();
                    string json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
                    await File.WriteAllTextAsync(_storagePath, json);
                }
                finally
                {
                    _lock.Release();
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "LocalReputation diske yazılırken hata oluştu.");
            }
        }

        public async Task RecordFileObservationAsync(
            string path,
            string sha256,
            string? originProcess = null,
            int? riskScore = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(sha256)) return;

            var record = _records.GetOrAdd(sha256, hash => new LocalReputationRecord
            {
                SHA256 = hash,
                FilePath = path,
                FirstSeenUtc = DateTime.UtcNow,
                LastSeenUtc = DateTime.UtcNow,
                OriginProcess = originProcess ?? string.Empty
            });

            record.LastSeenUtc = DateTime.UtcNow;
            record.ObservationCount++;
            if (!string.IsNullOrWhiteSpace(originProcess) && string.IsNullOrWhiteSpace(record.OriginProcess))
            {
                record.OriginProcess = originProcess;
            }
            if (riskScore.HasValue)
            {
                record.ScoreHistory.Add(riskScore.Value);
            }

            await SaveToDiskAsync();
        }

        public async Task RecordIncidentAsync(string sha256, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(sha256)) return;

            if (_records.TryGetValue(sha256, out var record))
            {
                record.HasMaliciousIncident = true;
                await SaveToDiskAsync();
            }
        }

        public Task<LocalReputationVerdict> EvaluateReputationAsync(string sha256, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(sha256) || !_records.TryGetValue(sha256, out var record))
            {
                return Task.FromResult(new LocalReputationVerdict
                {
                    ScoreModifier = 0,
                    Reason = "Yerel itibar kaydı yok (yeni dosya)",
                    AgeDays = 0,
                    IsLongTermClean = false
                });
            }

            int ageDays = (int)Math.Max(0, (DateTime.UtcNow - record.FirstSeenUtc).TotalDays);

            if (record.IsEligibleForLongTermCleanDiscount)
            {
                return Task.FromResult(new LocalReputationVerdict
                {
                    ScoreModifier = CleanAgeDiscountScore,
                    Reason = $"-10 Yerel İtibar: Dosya {ageDays} gündür (6+ ay) sistemde sorunsuz çalışıyor",
                    FirstSeenUtc = record.FirstSeenUtc,
                    AgeDays = ageDays,
                    IsLongTermClean = true
                });
            }

            return Task.FromResult(new LocalReputationVerdict
            {
                ScoreModifier = 0,
                Reason = $"Yerel İtibar: Dosya {ageDays} gündür gözlemleniyor (indirim eşiği 180 gün)",
                FirstSeenUtc = record.FirstSeenUtc,
                AgeDays = ageDays,
                IsLongTermClean = false
            });
        }
    }
}
