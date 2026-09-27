using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Detection.YaraEngine;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    /// <summary>Reports bounded ZIP-family member decisions and explicit unread or unsupported coverage.</summary>
    public class ArchiveScanResult
    {
        /// <summary>True when the source is identified as a ZIP-family container by structure or format hint.</summary>
        public bool IsArchive { get; set; }
        /// <summary>Indicates a resource-exhaustion compression anomaly, not an exact malware signature.</summary>
        public bool IsZipBomb { get; set; }
        /// <summary>False when any required member or configured rule inspection was omitted or failed.</summary>
        public bool IsComplete { get; set; } = true;
        /// <summary>Explains why a no-match result must not be published as complete clean coverage.</summary>
        public string? CoverageLimitation { get; set; }
        /// <summary>Counts encountered archive entries up to the configured inspection limits.</summary>
        public int TotalEntries { get; set; }
        /// <summary>Reports declared expanded sizes observed before a limit was reached.</summary>
        public long TotalUncompressedBytes { get; set; }
        /// <summary>Contains structural anomalies requiring investigation, without extracting their paths.</summary>
        public List<string> SuspiciousEntries { get; set; } = new();
        /// <summary>Contains member-level content or structural evidence; quarantine must target the outer source container.</summary>
        public List<SecurityFinding> Findings { get; set; } = new();
    }

    /// <summary>
    /// Inspects ZIP-family/JAR members with streaming hashes, patterns and optional configured in-memory YARA rules.
    /// Extraction never touches disk; nested, oversized or failed members remain partial instead of assumed clean.
    /// </summary>
    public class ArchiveSafetyScanner
    {
        private readonly ILogger<ArchiveSafetyScanner>? _logger;
        private readonly IYaraEngine? _yaraEngine;
        private const long MaxDecompressedSizeBytes = 500 * 1024 * 1024; // 500 MB İnceleme Limiti
        private const int MaxEntryCount = 25000; // 25,000 dosya sınırı
        private const double MaxCompressionRatio = 100.0; // 100:1 oranından fazla sıkıştırma = Zip Bomb şüphesi

        /// <summary>Uses an optional shared rule engine without loading extra rules or creating another engine instance.</summary>
        public ArchiveSafetyScanner(ILogger<ArchiveSafetyScanner>? logger = null, IYaraEngine? yaraEngine = null)
        {
            _logger = logger;
            _yaraEngine = yaraEngine;
        }

        /// <summary>Inspects at most 25,000 entries and 500 MiB expanded size; each content/rule member is bounded below 10 MiB.</summary>
        public async Task<ArchiveScanResult> ScanArchiveAsync(string filePath, CancellationToken cancellationToken = default)
        {
            var result = new ArchiveScanResult();
            if (!File.Exists(filePath)) return result;

            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            bool namedZip = ext is ".zip" or ".jar" or ".nupkg" or ".apk" or ".docx" or ".xlsx" or ".pptx" or ".docm" or ".xlsm" or ".pptm" or ".odt" or ".ods" or ".whl";
            using var headerStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            bool zipHeader = headerStream.ReadByte() == 0x50 && headerStream.ReadByte() == 0x4b;
            if (!namedZip && !zipHeader)
            {
                return result;
            }

            result.IsArchive = true;

            try
            {
                var fileInfo = new FileInfo(filePath);
                var compressedFileSize = fileInfo.Length;
                if (compressedFileSize == 0) return result;

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var archive = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: false);

                long totalUncompressed = 0;
                int count = 0;

                foreach (var entry in archive.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    count++;

                    // 1. Max Entry Limit (Kota aşılırsa taramayı güvenle durdur, asla virüs deme)
                    if (count > MaxEntryCount)
                    {
                        result.IsComplete = false;
                        result.CoverageLimitation = "Arşiv üye sayısı sınırı aşıldı.";
                        break;
                    }
                    if (result.Findings.Count >= 512)
                    {
                        result.IsComplete = false;
                        result.CoverageLimitation = "Arşiv bulgu sayısı sınırı aşıldı; kalan içerik tam incelenemedi.";
                        break;
                    }

                    // 2. Real Path Traversal Check (e.g. ../../Windows/System32)
                    var entryName = entry.FullName;
                    if (entryName.StartsWith("../") || entryName.StartsWith(@"..\") || entryName.Contains("/../") || entryName.Contains(@"\..\"))
                    {
                        result.SuspiciousEntries.Add($"Path Traversal tespit edildi: '{entryName}'");
                        result.Findings.Add(new SecurityFinding
                        {
                            ObjectPath = filePath,
                            ObjectName = Path.GetFileName(filePath),
                            Category = FindingCategory.MalwareSuspicion,
                            RiskLevel = RiskLevel.HighRisk,
                            RiskScore = 90,
                            Title = $"Arşiv Path Traversal Zafiyeti: {entry.Name}",
                            Description = $"Arşiv içindeki '{entryName}' dosyası sistem dizinlerinin üzerine yazmayı amaçlıyor.",
                            ConfidenceLevel = ConfidenceLevel.High
                        });
                    }

                    // 3. Accumulate uncompressed size
                    totalUncompressed = checked(totalUncompressed + entry.Length);
                    if (totalUncompressed > MaxDecompressedSizeBytes)
                    {
                        result.IsComplete = false;
                        result.CoverageLimitation = "Arşiv açılmış boyut bütçesi aşıldı (500 MB).";
                        break;
                    }

                    // Zip Bomb Denetimi: Sadece oran 100:1'den büyük VE sıkıştırılmış boyut küçükken tetiklenir (örn: 10MB -> 2GB)
                    double entryRatio = entry.CompressedLength > 0 ? (double)entry.Length / entry.CompressedLength : 1.0;
                    if (entryRatio > MaxCompressionRatio && entry.Length > 50 * 1024 * 1024)
                    {
                        result.IsZipBomb = true;
                        result.IsComplete = false;
                        result.CoverageLimitation = "Aşırı sıkıştırma nedeniyle inceleme durduruldu.";
                        result.SuspiciousEntries.Add($"Anormal sıkıştırma oranı tespit edildi ({entryRatio:F0}:1). Zip-Bomb saldırı deseni.");
                        result.Findings.Add(new SecurityFinding
                        {
                            ObjectPath = filePath,
                            ObjectName = Path.GetFileName(filePath),
                            Category = FindingCategory.HighResourceUsage,
                            RiskLevel = RiskLevel.HighRisk,
                            RiskScore = 90,
                            Title = "Zip-Bomb Kaynak Tüketim Saldırısı",
                            Description = $"Aşırı sıkıştırılmış veri deseni tespit edildi (Genişleme oranı: {entryRatio:F0}:1).",
                            ConfidenceLevel = ConfidenceLevel.High
                        });
                        break;
                    }

                    // 4. Inspect embedded executables with quick signature check
                    var entryExt = Path.GetExtension(entry.Name).ToLowerInvariant();
                    if (entryExt is ".zip" or ".jar" or ".nupkg" or ".apk" ||
                        entry.Length >= 10 * 1024 * 1024)
                    {
                        result.IsComplete = false;
                        result.CoverageLimitation = "İç içe arşiv veya inceleme sınırını aşan gömülü dosya mevcut.";
                    }
                    if (entry.Length > 0 && entry.Length < 10 * 1024 * 1024)
                    {
                        try
                        {
                            IYaraEngine? rules = _yaraEngine;
                            if (rules != null && (rules.LoadedRuleCount == 0 ||
                                (rules.MaximumScanBytes.HasValue && entry.Length > rules.MaximumScanBytes.Value)))
                            {
                                result.IsComplete = false;
                                result.CoverageLimitation = "Gömülü dosyanın yapılandırılmış YARA incelemesi kullanılamıyor veya boyut sınırını aşıyor.";
                                rules = null;
                            }
                            var (sha256, patternMatch, nestedContainer, yaraMatches) = await ArchiveEntryInspector.InspectAsync(entry, cancellationToken, rules);
                            if (nestedContainer)
                            {
                                result.IsComplete = false;
                                result.CoverageLimitation = "İç içe arşiv içeriği özyinelemeli incelenmedi.";
                            }
                            var match = MalwareSignatureDatabase.CheckHash(sha256);
                            if (match.IsMatched || patternMatch.IsMatched)
                            {
                                bool confirmed = match.IsMatched || patternMatch.ThreatCategory.Equals("TestMalware", StringComparison.OrdinalIgnoreCase);
                                var threatName = match.IsMatched 
                                    ? match.ThreatName 
                                    : (patternMatch.IsMatched ? patternMatch.ThreatName : "EICAR-Standard-AV-Test");

                                int score = confirmed ? (match.IsMatched ? match.SeverityScore : patternMatch.SeverityScore) : Math.Min(65, patternMatch.SeverityScore);

                                result.Findings.Add(new SecurityFinding
                                {
                                    ObjectPath = $"{filePath} -> {entry.FullName}",
                                    ObjectName = entry.Name,
                                    SHA256 = sha256,
                                    Category = confirmed ? FindingCategory.KnownMalwareHash : FindingCategory.SuspiciousScript,
                                    RiskLevel = confirmed ? RiskLevel.ConfirmedMalicious : RiskLevel.Suspicious,
                                    RiskScore = score,
                                    Title = $"Arşiv İçinde Tehdit: {threatName}",
                                    Description = $"Arşivin içindeki '{entry.FullName}' dosyası zararlı imza/kod deseni içeriyor.",
                                    ConfidenceLevel = ConfidenceLevel.High
                                });
                            }
                            int ruleBudget = Math.Max(0, 512 - result.Findings.Count);
                            foreach (var rule in yaraMatches.Take(ruleBudget))
                            {
                                // Local rule names and self-declared confidence are not equivalent to confirmed malware intelligence.
                                result.Findings.Add(new SecurityFinding
                                {
                                    ObjectPath = $"{filePath} -> {entry.FullName}", ObjectName = entry.Name, SHA256 = sha256,
                                    Category = FindingCategory.MalwareSuspicion, RiskLevel = RiskLevel.Suspicious,
                                    RiskScore = Math.Clamp(rule.Severity > 0 ? rule.Severity : 65, 1, 75),
                                    Title = $"Arşiv Üyesinde YARA Kuralı: {rule.RuleName}",
                                    Description = $"'{entry.FullName}' içinde '{rule.RuleName}' kuralı eşleşti. Bu tek başına doğrulanmış zararlı kanıtı değildir. {rule.Description}",
                                    ConfidenceLevel = ConfidenceLevel.Medium,
                                    RiskReasons = new List<string> { $"Archive member: {entry.FullName}", $"YARA rule: {rule.RuleName}", $"Member SHA-256: {sha256}" }
                                });
                            }
                            if (yaraMatches.Count > ruleBudget)
                            {
                                result.IsComplete = false;
                                result.CoverageLimitation = "Arşiv kural bulguları çıktı sınırına ulaştı.";
                            }
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                        catch (Exception ex)
                        {
                            result.IsComplete = false;
                            result.CoverageLimitation = "Arşiv üyesi okunamadı.";
                            _logger?.LogWarning(ex, "Failed to scan archive entry {Entry} in {File}", entry.FullName, filePath);
                        }
                    }
                }

                // 5. Ratio check
                double ratio = compressedFileSize > 0 ? (double)totalUncompressed / compressedFileSize : 0;
                if (ratio > MaxCompressionRatio && totalUncompressed > 50 * 1024 * 1024)
                {
                    result.IsZipBomb = true;
                    result.SuspiciousEntries.Add($"Anormal sıkıştırma oranı: {ratio:F1}:1.");
                }

                result.TotalEntries = count;
                result.TotalUncompressedBytes = totalUncompressed;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                result.IsComplete = false;
                result.CoverageLimitation = "Arşiv okunamadı: " + ex.Message;
                _logger?.LogWarning(ex, "Archive scanning error on {Path}", filePath);
            }

            return result;
        }
    }
}
