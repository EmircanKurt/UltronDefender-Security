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
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class ArchiveScanResult
    {
        public bool IsArchive { get; set; }
        public bool IsZipBomb { get; set; }
        public int TotalEntries { get; set; }
        public long TotalUncompressedBytes { get; set; }
        public List<string> SuspiciousEntries { get; set; } = new();
        public List<SecurityFinding> Findings { get; set; } = new();
    }

    /// <summary>
    /// Zip-Bomb, iç içe aşırı sıkıştırma (nested decompression explosion),
    /// Path Traversal ve arşiv içi gömülü zararlı dosya tespit motoru.
    /// </summary>
    public class ArchiveSafetyScanner
    {
        private readonly ILogger<ArchiveSafetyScanner>? _logger;
        private const long MaxDecompressedSizeBytes = 250 * 1024 * 1024; // 250 MB Limit
        private const int MaxEntryCount = 1000;
        private const double MaxCompressionRatio = 100.0; // 100:1 oranından fazla sıkıştırma = Zip Bomb şüphesi

        private static readonly string[] ExecutableExtensions = new[]
        {
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".wsf", ".msi", ".com", ".cpl"
        };

        public ArchiveSafetyScanner(ILogger<ArchiveSafetyScanner>? logger = null)
        {
            _logger = logger;
        }

        public async Task<ArchiveScanResult> ScanArchiveAsync(string filePath, CancellationToken cancellationToken = default)
        {
            var result = new ArchiveScanResult();
            if (!File.Exists(filePath)) return result;

            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext != ".zip" && ext != ".jar" && ext != ".nupkg")
            {
                return result;
            }

            result.IsArchive = true;

            try
            {
                var compressedFileSize = new FileInfo(filePath).Length;
                if (compressedFileSize == 0) return result;

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var archive = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: false);

                long totalUncompressed = 0;
                int count = 0;

                foreach (var entry in archive.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    count++;

                    // 1. Max Entry Limit
                    if (count > MaxEntryCount)
                    {
                        result.IsZipBomb = true;
                        result.SuspiciousEntries.Add($"Arşiv izin verilen maksimum dosya sayısını aştı (> {MaxEntryCount}).");
                        break;
                    }

                    // 2. Path Traversal Check (e.g. ../../Windows/System32)
                    var entryName = entry.FullName;
                    if (entryName.Contains("..") || Path.IsPathRooted(entryName))
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
                    totalUncompressed += entry.Length;
                    if (totalUncompressed > MaxDecompressedSizeBytes)
                    {
                        result.IsZipBomb = true;
                        result.SuspiciousEntries.Add($"Arşiv açılmış boyutu limit sınırını aştı (> 250 MB). Zip-Bomb saldırı deseni.");
                        result.Findings.Add(new SecurityFinding
                        {
                            ObjectPath = filePath,
                            ObjectName = Path.GetFileName(filePath),
                            Category = FindingCategory.HighResourceUsage,
                            RiskLevel = RiskLevel.HighRisk,
                            RiskScore = 85,
                            Title = "Zip-Bomb Kaynak Tüketim Saldırısı",
                            Description = "Aşırı sıkıştırılmış veri deseni (RAM/Disk çökertme girişimi) engellendi.",
                            ConfidenceLevel = ConfidenceLevel.High
                        });
                        break;
                    }

                    // 4. Inspect embedded executables with quick signature check
                    var entryExt = Path.GetExtension(entry.Name).ToLowerInvariant();
                    if (ExecutableExtensions.Contains(entryExt) && entry.Length > 0 && entry.Length < 10 * 1024 * 1024)
                    {
                        try
                        {
                            using var entryStream = entry.Open();
                            using var ms = new MemoryStream();
                            await entryStream.CopyToAsync(ms, cancellationToken);
                            var bytes = ms.ToArray();
                            var sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));

                            var match = MalwareSignatureDatabase.CheckHash(sha256);
                            var patternMatch = MalwareSignatureDatabase.CheckBytesPattern(bytes);
                            var text = Encoding.ASCII.GetString(bytes);

                            if (match.IsMatched || patternMatch.IsMatched || text.Contains("EICAR", StringComparison.OrdinalIgnoreCase) || text.Contains("powershell", StringComparison.OrdinalIgnoreCase) || text.Contains("vssadmin", StringComparison.OrdinalIgnoreCase))
                            {
                                var threatName = match.IsMatched 
                                    ? match.ThreatName 
                                    : (patternMatch.IsMatched ? patternMatch.ThreatName : (text.Contains("EICAR") ? "EICAR-Standard-AV-Test" : "Trojan.Script.Dropper"));

                                int score = match.IsMatched ? match.SeverityScore : (patternMatch.IsMatched ? patternMatch.SeverityScore : 90);

                                result.Findings.Add(new SecurityFinding
                                {
                                    ObjectPath = $"{filePath} -> {entry.FullName}",
                                    ObjectName = entry.Name,
                                    SHA256 = sha256,
                                    Category = FindingCategory.KnownMalwareHash,
                                    RiskLevel = RiskLevel.HighRisk,
                                    RiskScore = score,
                                    Title = $"Arşiv İçinde Tehdit: {threatName}",
                                    Description = $"Arşivin içindeki '{entry.FullName}' dosyası zararlı imza/kod deseni içeriyor.",
                                    ConfidenceLevel = ConfidenceLevel.High
                                });
                            }
                        }
                        catch { }
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
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Archive scanning error on {Path}", filePath);
            }

            return result;
        }
    }
}
