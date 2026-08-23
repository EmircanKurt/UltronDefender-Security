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
        private const long MaxDecompressedSizeBytes = 500 * 1024 * 1024; // 500 MB İnceleme Limiti
        private const int MaxEntryCount = 25000; // 25,000 dosya sınırı
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

            // Oyun ve mod dizinlerindeki arşivleri (BeamNG araçları, haritalar, modlar) false-positive ve bellek yükünden koru
            if (AegisPC.Core.Helpers.PathHelper.IsGameOrRepackDirectory(filePath) || AegisPC.Core.Helpers.GameCrackClassifier.IsGameCrackOrEmulator(filePath))
            {
                return result;
            }

            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext != ".zip" && ext != ".jar" && ext != ".nupkg")
            {
                return result;
            }

            result.IsArchive = true;

            try
            {
                var fileInfo = new FileInfo(filePath);
                var compressedFileSize = fileInfo.Length;
                if (compressedFileSize == 0 || compressedFileSize > 100 * 1024 * 1024) return result; // 100 MB üzeri devasa arşivleri atla

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
                    totalUncompressed += entry.Length;

                    // Zip Bomb Denetimi: Sadece oran 100:1'den büyük VE sıkıştırılmış boyut küçükken tetiklenir (örn: 10MB -> 2GB)
                    double entryRatio = entry.CompressedLength > 0 ? (double)entry.Length / entry.CompressedLength : 1.0;
                    if (entryRatio > MaxCompressionRatio && entry.Length > 50 * 1024 * 1024)
                    {
                        result.IsZipBomb = true;
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
                    if (ExecutableExtensions.Contains(entryExt) && entry.Length > 0 && entry.Length < 10 * 1024 * 1024)
                    {
                        int sampleSize = Math.Min((int)entry.Length, 256 * 1024);
                        byte[] sampleBuffer = System.Buffers.ArrayPool<byte>.Shared.Rent(sampleSize);
                        try
                        {
                            int totalSampleRead = 0;
                            using var incHash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
                            using var entryStream = entry.Open();
                            
                            byte[] chunk = System.Buffers.ArrayPool<byte>.Shared.Rent(8192);
                            try
                            {
                                int read;
                                while ((read = await entryStream.ReadAsync(chunk.AsMemory(0, 8192), cancellationToken)) > 0)
                                {
                                    incHash.AppendData(chunk, 0, read);
                                    if (totalSampleRead < sampleSize)
                                    {
                                        int toCopy = Math.Min(read, sampleSize - totalSampleRead);
                                        Buffer.BlockCopy(chunk, 0, sampleBuffer, totalSampleRead, toCopy);
                                        totalSampleRead += toCopy;
                                    }
                                }
                            }
                            finally
                            {
                                System.Buffers.ArrayPool<byte>.Shared.Return(chunk);
                            }

                            var sha256 = Convert.ToHexString(incHash.GetHashAndReset());
                            var match = MalwareSignatureDatabase.CheckHash(sha256);
                            var text = totalSampleRead > 0 ? Encoding.ASCII.GetString(sampleBuffer, 0, totalSampleRead) : string.Empty;
                            var patternMatch = !string.IsNullOrEmpty(text) ? MalwareSignatureDatabase.CheckContentString(text) : new MalwareSignatureMatch();

                            // Yalnızca gerçek doğrulanmış malware hash'i veya kesin exploit deseni varsa işaretle
                            if (match.IsMatched || patternMatch.IsMatched || text.Contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", StringComparison.OrdinalIgnoreCase))
                            {
                                var threatName = match.IsMatched 
                                    ? match.ThreatName 
                                    : (patternMatch.IsMatched ? patternMatch.ThreatName : "EICAR-Standard-AV-Test");

                                int score = match.IsMatched ? match.SeverityScore : (patternMatch.IsMatched ? patternMatch.SeverityScore : 100);

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
                        finally
                        {
                            System.Buffers.ArrayPool<byte>.Shared.Return(sampleBuffer);
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
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Archive scanning error on {Path}", filePath);
            }

            return result;
        }
    }
}
