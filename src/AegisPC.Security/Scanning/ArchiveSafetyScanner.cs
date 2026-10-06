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
        /// <summary>True for ZIP-family or unsupported container candidates; format hints alone do not validate structure or safety.</summary>
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
        /// <summary>Counts members whose entire decompressed stream was actually hashed, including large members.</summary>
        public int HashedMembers { get; set; }
        /// <summary>Reports successfully hashed expanded bytes, not merely metadata-declared sizes.</summary>
        public long HashedExpandedBytes { get; set; }
        /// <summary>Contains up to 256 member hash summaries; output truncation does not imply those other members were clean.</summary>
        public List<ArchiveMemberHashSummary> MemberHashes { get; set; } = new();
        /// <summary>Contains structural anomalies requiring investigation, without extracting their paths.</summary>
        public List<string> SuspiciousEntries { get; set; } = new();
        /// <summary>Contains member-level content or structural evidence; quarantine must target the outer source container.</summary>
        public List<SecurityFinding> Findings { get; set; } = new();
    }

    /// <summary>
    /// Inspects ZIP-family/JAR members with streaming hashes, patterns and optional configured in-memory YARA rules.
    /// Extraction never touches disk; nested, oversized or failed members remain partial instead of assumed clean.
    /// </summary>
    public partial class ArchiveSafetyScanner
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

        /// <summary>Inspects at most 25,000 outer entries and 500 MiB expanded size; nested ZIP members have separate 8-archive, 256-entry and 32 MiB bounds, and remain partial coverage.</summary>
        public async Task<ArchiveScanResult> ScanArchiveAsync(string filePath, CancellationToken cancellationToken = default, bool contentIdentifiedZip = false)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = new ArchiveScanResult();
            if (!File.Exists(filePath))
            {
                result.IsComplete = false;
                result.CoverageLimitation = "Arşiv dosyası bulunamadı veya erişilemiyor.";
                return result;
            }

            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            bool namedZip = ext is ".zip" or ".jar" or ".nupkg" or ".apk" or ".docx" or ".xlsx" or ".pptx" or ".docm" or ".xlsm" or ".pptm" or ".odt" or ".ods" or ".whl";
            bool zipHeader;
            bool unsupportedContainer;
            try
            {
                using var headerStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] header = new byte[6];
                int read = headerStream.Read(header, 0, header.Length);
                zipHeader = read >= 2 && header[0] == 0x50 && header[1] == 0x4b;
                unsupportedContainer = !zipHeader && ArchiveEntryInspector.HasContainerHeader(header.AsSpan(0, read));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                result.IsComplete = false;
                result.CoverageLimitation = "Arşiv başlığı okunamadı; temiz kabul edilmedi.";
                _logger?.LogWarning(ex, "Archive header could not be read");
                return result;
            }
            if (!namedZip && !zipHeader && !contentIdentifiedZip)
            {
                if (unsupportedContainer || ext is ".rar" or ".7z" or ".gz" or ".bz2" or ".xz" or ".cab")
                {
                    result.IsArchive = true;
                    result.IsComplete = false;
                    result.CoverageLimitation = "Arşiv adayı; bu biçimin üyeleri mevcut ZIP çözümleyicisiyle incelenmedi.";
                }
                return result;
            }

            result.IsArchive = true;

            try
            {
                var fileInfo = new FileInfo(filePath);
                var compressedFileSize = fileInfo.Length;
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var archive = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: false);

                long totalUncompressed = 0;
                int count = 0;
                var nestedBudget = new NestedArchiveInspectionBudget();

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
                    if (entry.Length >= 10 * 1024 * 1024)
                    {
                        result.IsComplete = false;
                        result.CoverageLimitation = "Büyük üye akış halinde hash/desen kontrolünden geçer; tampon tabanlı kural ve derin yapı incelemesi kısmi.";
                    }
                    if (entry.Length > 0)
                    {
                        try
                        {
                            IYaraEngine? rules = _yaraEngine;
                            if (entry.Length >= 10 * 1024 * 1024) rules = null;
                            if (rules != null && (rules.LoadedRuleCount == 0 ||
                                (rules.MaximumScanBytes.HasValue && entry.Length > rules.MaximumScanBytes.Value)))
                            {
                                result.IsComplete = false;
                                result.CoverageLimitation = "Gömülü dosyanın yapılandırılmış YARA incelemesi kullanılamıyor veya boyut sınırını aşıyor.";
                                rules = null;
                            }
                            var (sha256, patternMatch, nestedContainer, yaraMatches) = await ArchiveEntryInspector.InspectAsync(entry, cancellationToken, rules);
                            result.HashedMembers++;
                            result.HashedExpandedBytes = checked(result.HashedExpandedBytes + entry.Length);
                            if (result.MemberHashes.Count < 256)
                                result.MemberHashes.Add(new(entry.FullName[..Math.Min(entry.FullName.Length, 512)], sha256, entry.Length));
                            if (nestedContainer)
                            {
                                result.IsComplete = false;
                                result.CoverageLimitation = "İç içe kapsayıcı içeriğinin kapsamı kısmi.";
                                if (entry.Length < 10 * 1024 * 1024)
                                    await InspectNestedZipAsync(entry, filePath, result, nestedBudget, cancellationToken);
                            }
                            var match = MalwareSignatureDatabase.CheckHash(sha256);
                            if (match.IsMatched || patternMatch.IsMatched)
                            {
                                bool confirmed = MalwareSignatureDatabase.IsTrustedEmbeddedHash(sha256);
                                var threatName = match.IsMatched 
                                    ? match.ThreatName 
                                    : (patternMatch.IsMatched ? patternMatch.ThreatName : "EICAR-Standard-AV-Test");

                                int severity = match.IsMatched ? match.SeverityScore : patternMatch.SeverityScore;
                                int score = confirmed ? severity : Math.Min(65, severity);

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
                    result.IsComplete = false;
                    result.CoverageLimitation ??= "Arşivin toplam sıkıştırma oranı kaynak tüketimi incelemesi gerektiriyor; tam kapsam sonucu verilmedi.";
                    result.SuspiciousEntries.Add($"Anormal sıkıştırma oranı: {ratio:F1}:1.");
                }

                result.TotalEntries += count;
                result.TotalUncompressedBytes += totalUncompressed;
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
