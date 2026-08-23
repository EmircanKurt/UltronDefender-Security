using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Archive;
using AegisPC.Contracts.Detection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Archive
{
    /// <summary>
    /// Sıkıştırılmış arşivleri (ZIP) Zip Bomb / Decompression Bomb saldırılarına karşı
    /// sıkı kota ve genişleme sınırlarıyla güvenle açan ve analiz eden motor.
    /// </summary>
    public class SecureArchiveEngine : ISecureArchiveEngine
    {
        private readonly ILogger<SecureArchiveEngine>? _logger;

        private static readonly HashSet<string> DangerousPayloadExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".iso", ".dll", ".sys", ".cpl"
        };

        public SecureArchiveEngine(ILogger<SecureArchiveEngine>? logger = null)
        {
            _logger = logger;
        }

        public async Task<ArchiveScanVerdict> InspectArchiveAsync(string filePath, ArchiveSafetyLimits? limits = null, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new ArchiveScanVerdict { IsValidArchive = false };
            }

            try
            {
                await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.SequentialScan | FileOptions.Asynchronous);
                return InspectArchiveStreamInternal(fs, limits ?? new ArchiveSafetyLimits(), currentDepth: 1, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Archive inspection failed for {Path}", filePath);
                return new ArchiveScanVerdict { IsValidArchive = false, Explanation = ex.Message };
            }
        }

        public Task<ArchiveScanVerdict> InspectArchiveStreamAsync(Stream stream, ArchiveSafetyLimits? limits = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(InspectArchiveStreamInternal(stream, limits ?? new ArchiveSafetyLimits(), currentDepth: 1, cancellationToken));
        }

        private ArchiveScanVerdict InspectArchiveStreamInternal(
            Stream stream,
            ArchiveSafetyLimits limits,
            int currentDepth,
            CancellationToken cancellationToken)
        {
            var verdict = new ArchiveScanVerdict
            {
                IsValidArchive = true,
                DeepestLevel = currentDepth
            };

            if (currentDepth > limits.MaxNestedDepth)
            {
                verdict.IsDepthExceeded = true;
                verdict.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.ArchiveAnomaly,
                    RuleName = "ARCHIVE_NESTED_DEPTH_EXCEEDED",
                    ScoreContribution = 40,
                    Confidence = EvidenceConfidence.High,
                    Description = $"İç içe arşiv derinlik sınırı ({limits.MaxNestedDepth} seviye) aşıldı (Derinlik: {currentDepth})."
                });
                verdict.Explanation = "İç içe çok derin arşiv yapısı (Anti-AV evasion / Zip Bomb).";
                return verdict;
            }

            try
            {
                using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
                verdict.TotalEntryCount = archive.Entries.Count;

                if (verdict.TotalEntryCount > limits.MaxEntryCount)
                {
                    verdict.IsQuotaExceeded = true;
                    verdict.Explanation = $"Arşiv inceleme dosya sayısı kotası aşıldı ({verdict.TotalEntryCount} > {limits.MaxEntryCount}).";
                    return verdict;
                }

                long accumulatedUncompressed = 0;
                long accumulatedCompressed = 0;
                double maxRatio = 0.0;

                foreach (var entry in archive.Entries)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    accumulatedCompressed += entry.CompressedLength;
                    accumulatedUncompressed += entry.Length;

                    // Genişleme Oranı Hesaplaması (Compression Ratio)
                    double ratio = entry.CompressedLength > 0 ? (double)entry.Length / entry.CompressedLength : 1.0;
                    if (ratio > maxRatio) maxRatio = ratio;

                    // 1. Tekil Dosya Zip Bomb Sınırı
                    if (ratio > limits.MaxCompressionRatio && entry.Length > 1024 * 1024)
                    {
                        verdict.HasZipBomb = true;
                        verdict.Evidences.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.ArchiveAnomaly,
                            RuleName = "ARCHIVE_ZIP_BOMB_RATIO_EXCEEDED",
                            ScoreContribution = 85,
                            Confidence = EvidenceConfidence.Absolute,
                            Description = $"Zip Bomb Genişleme Oranı Tespiti: '{entry.FullName}' için oran {ratio:F1}:1 (Sınır: {limits.MaxCompressionRatio}:1)."
                        });
                    }

                    // 2. Toplam Açılmış Boyut Kota Sınırı
                    if (accumulatedUncompressed > limits.MaxTotalUncompressedBytes)
                    {
                        verdict.IsQuotaExceeded = true;
                        verdict.Evidences.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.ArchiveAnomaly,
                            RuleName = "ARCHIVE_TOTAL_SIZE_QUOTA_EXCEEDED",
                            ScoreContribution = 30,
                            Confidence = EvidenceConfidence.High,
                            Description = $"Toplam açılmış arşiv boyut kotası aşıldı ({accumulatedUncompressed / 1024 / 1024} MB > {limits.MaxTotalUncompressedBytes / 1024 / 1024} MB)."
                        });
                        break;
                    }

                    // 3. Şüpheli İkili / Yürütülebilir Dosya Varlığı
                    var ext = Path.GetExtension(entry.FullName).ToLowerInvariant();
                    if (DangerousPayloadExtensions.Contains(ext))
                    {
                        verdict.SuspiciousFileNames.Add(entry.FullName);
                        verdict.Evidences.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.ArchiveAnomaly,
                            RuleName = "ARCHIVE_EMBEDDED_EXECUTABLE_PAYLOAD",
                            ScoreContribution = 20,
                            Confidence = EvidenceConfidence.Medium,
                            Description = $"Arşiv içerisinde doğrudan yürütülebilir dosya tespit edildi: '{entry.FullName}'"
                        });
                    }

                    // 4. İç İçe Arşiv Taraması (.zip içinde .zip)
                    if (ext is ".zip" && entry.Length > 0 && entry.Length < 10 * 1024 * 1024)
                    {
                        try
                        {
                            using var nestedStream = entry.Open();
                            using var ms = new MemoryStream();
                            nestedStream.CopyTo(ms);
                            ms.Position = 0;

                            var nestedVerdict = InspectArchiveStreamInternal(ms, limits, currentDepth + 1, cancellationToken);
                            verdict.DeepestLevel = Math.Max(verdict.DeepestLevel, nestedVerdict.DeepestLevel);
                            verdict.Evidences.AddRange(nestedVerdict.Evidences);
                            if (nestedVerdict.HasZipBomb) verdict.HasZipBomb = true;
                            if (nestedVerdict.IsDepthExceeded) verdict.IsDepthExceeded = true;
                        }
                        catch { }
                    }
                }

                verdict.TotalCompressedBytes = accumulatedCompressed;
                verdict.TotalUncompressedBytes = accumulatedUncompressed;
                verdict.HighestCompressionRatio = maxRatio;

                if (verdict.HasZipBomb)
                {
                    verdict.Explanation = "🚨 Zararlı Zip Bomb / Decompression Bomb saldırı deseni tespit edildi.";
                }
                else if (verdict.SuspiciousFileNames.Count > 0)
                {
                    verdict.Explanation = $"Arşiv {verdict.SuspiciousFileNames.Count} adet yürütülebilir/komut dosyası içeriyor.";
                }
                else
                {
                    verdict.Explanation = "Arşiv yapısı temiz ve güvenlik sınırları dahilinde.";
                }
            }
            catch (InvalidDataException)
            {
                verdict.IsValidArchive = false;
                verdict.Explanation = "Geçersiz veya bozuk arşiv formatı.";
            }
            catch (Exception ex)
            {
                verdict.IsValidArchive = false;
                verdict.Explanation = ex.Message;
            }

            return verdict;
        }
    }
}
