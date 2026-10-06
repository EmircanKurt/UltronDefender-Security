using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning;

/// <summary>Per-file inspection holds identity stable across classification, hashing and common detector routing.</summary>
public partial class FileScannerService
{
        /// <summary>Returns observed evidence, not a completeness guarantee; use the detailed API for unavailable inspection.</summary>
        public async Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default)
        {
            var detailed = await ScanFileDetailedAsync(path, TimeSpan.FromSeconds(10), cancellationToken);
            return detailed.Finding;
        }

        /// <summary>Classifies and inspects a locked source with explicit limits and cancellation; incomplete content is never cached as clean.</summary>
        public async Task<FileScanDetailedResult> ScanFileDetailedAsync(
            string path,
            TimeSpan perFileTimeout,
            CancellationToken cancellationToken = default)
        {
            var sw = Stopwatch.StartNew();
            FileContentClassification? classification = null;
            FileScanDetailedResult Classified(FileScanDetailedResult detailed)
            {
                detailed.ContentClassification = classification;
                return detailed;
            }
            long policyRevision = DetectionPolicyRevision.Current;
            cancellationToken.ThrowIfCancellationRequested();

            if (!File.Exists(path))
            {
                return FileScanDetailedResult.CreateSkipped(path, "Dosya mevcut değil");
            }

            // Per-file timeout koruması: Kilitli dosya veya askıda kalan işlem tüm taramayı donduramaz
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linkedCts.CancelAfter(perFileTimeout);

            try
            {
                // Hold identity stable across hash, analysis and publication of the completed cache entry.
                using var scanLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                var fileInfo = new FileInfo(path);
                if (fileInfo.Length == 0)
                {
                    return FileScanDetailedResult.CreateSkipped(path, "Boş dosya");
                }

                var ext = fileInfo.Extension.ToLowerInvariant();
                classification = await _contentClassifier.ClassifyAsync(scanLock, ext, linkedCts.Token);
                ArchiveScanResult? completedArchiveInspection = null;

                // Multi-Tier Caching: Değişmemiş temiz dosyalar için derin dedektör taramasını atla
                var cache = await _hashMatcher.TryGetCachedAsync(path, fileInfo, linkedCts.Token);
                var cachedFinding = cache.Finding;
                if (cache.Hit && (classification.IsComplete ||
                    cachedFinding is { RiskLevel: RiskLevel.ConfirmedMalicious, Status: not FindingStatus.Resolved, IsAllowlisted: false }))
                {
                    if (cachedFinding == null || cachedFinding.Status == FindingStatus.Resolved || cachedFinding.IsAllowlisted)
                    {
                        return Classified(FileScanDetailedResult.CreateSuccess(path, null, sw.Elapsed, isFromCache: true));
                    }
                    return Classified(classification.IsComplete
                        ? FileScanDetailedResult.CreateSuccess(path, cachedFinding, sw.Elapsed, isFromCache: true)
                        : FileScanDetailedResult.CreateFailed(path, string.Join("; ", classification.CoverageLimitations), sw.Elapsed, cachedFinding));
                }

                // 1. SHA256 Hesaplama & Güvenli Beyaz Liste / Çözüldü & Fast-Path WHQL İmza
                var (sha256, isAllowlisted, isMicrosoftBypassed) = await _hashMatcher.EvaluateHashAndAllowlistAsync(path, linkedCts.Token, cache.VerifiedHash);
                if (isAllowlisted || isMicrosoftBypassed)
                {
                    fileInfo.Refresh();
                    if (classification.IsComplete)
                        _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, null, sha256, isAllowlisted, isMicrosoftBypassed, policyRevision);
                    return Classified(classification.IsComplete
                        ? FileScanDetailedResult.CreateSuccess(path, null, sw.Elapsed, isSignedClean: true)
                        : FileScanDetailedResult.CreateFailed(path, string.Join("; ", classification.CoverageLimitations), sw.Elapsed));
                }

                cancellationToken.ThrowIfCancellationRequested();

                // A positive whole-file hash must not be lost behind a container parser limit.
                if (MalwareSignatureDatabase.CheckHash(sha256).IsMatched || ThreatSignatureDatabase.CheckHash(sha256).IsMatched)
                {
                    var knownInspection = await _pupCoordinator.AnalyzeLockedContentDetailedAsync(path, fileInfo, sha256, classification, null, scanLock, linkedCts.Token);
                    var knownFinding = knownInspection.Finding;
                    if (knownFinding != null)
                    {
                        if (knownInspection.IsComplete)
                            _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, knownFinding, sha256, false, false, policyRevision);
                        return Classified(knownInspection.IsComplete
                            ? FileScanDetailedResult.CreateSuccess(path, knownFinding, sw.Elapsed)
                            : FileScanDetailedResult.CreateFailed(path, string.Join("; ", knownInspection.CoverageLimitations), sw.Elapsed, knownFinding));
                    }
                }

                // 2. Arşiv Dosyası Güvenlik Taraması (Zip bomb, path traversal, nested payload)
                // Kural 27 gereğince: Yol güveni tamamen kaldırıldı (isGameDir = false)
                byte[] containerHeader = new byte[6];
                int headerBytes = await scanLock.ReadAtLeastAsync(containerHeader,
                    (int)Math.Min(fileInfo.Length, containerHeader.Length), false, linkedCts.Token);
                bool zipHeader = headerBytes >= 2 && containerHeader[0] == 0x50 && containerHeader[1] == 0x4b;
                if (classification.RequiresZipInspection || zipHeader || ext is ".zip" or ".jar" or ".nupkg" or ".apk" or ".docx" or ".xlsx" or ".pptx" or ".docm" or ".xlsm" or ".pptm" or ".odt" or ".ods" or ".whl")
                {
                    var archiveResult = await _archiveScanner.ScanArchiveAsync(path, linkedCts.Token, classification.RequiresZipInspection);
                    completedArchiveInspection = archiveResult;
                    if (archiveResult.Findings.Count > 0)
                    {
                        var topFinding = archiveResult.Findings.OrderByDescending(f => f.RiskScore).First();
                        if (topFinding.Status != FindingStatus.Resolved && !topFinding.IsAllowlisted)
                        {
                            // Containment targets the outer, locked container, not a synthetic "zip -> member" path.
                            topFinding.RiskReasons.Add($"Archive member: {topFinding.ObjectPath}; member SHA-256: {topFinding.SHA256}");
                            topFinding.ObjectPath = path;
                            topFinding.ObjectName = fileInfo.Name;
                            topFinding.SHA256 = sha256;
                            if (_findingService != null)
                            {
                                await _findingService.AddFindingAsync(topFinding, linkedCts.Token);
                            }
                            fileInfo.Refresh();
                            if (archiveResult.IsComplete && classification.IsComplete)
                                _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, topFinding, sha256, false, false, policyRevision);
                            else
                                return Classified(FileScanDetailedResult.CreateFailed(path,
                                    archiveResult.CoverageLimitation ?? string.Join("; ", classification.CoverageLimitations.DefaultIfEmpty("Arşiv incelemesi kısmi kaldı.")), sw.Elapsed, topFinding));
                            return Classified(FileScanDetailedResult.CreateSuccess(path, topFinding, sw.Elapsed, isFromCache: false, isSignedClean: false));
                        }
                    }
                    if (!archiveResult.IsComplete)
                        return Classified(FileScanDetailedResult.CreateFailed(path, archiveResult.CoverageLimitation ?? "Arşiv incelemesi kısmi kaldı.", sw.Elapsed));
                }
                else if (ArchiveEntryInspector.HasContainerHeader(containerHeader.AsSpan(0, headerBytes)) ||
                    ext is ".7z" or ".rar" or ".iso" or ".img" or ".tar" or ".gz" or ".cab" or ".bz2" or ".xz")
                {
                    // Whole-file hash remains checked; unsupported unpacking must never be cached as full coverage.
                    return Classified(FileScanDetailedResult.CreateFailed(path, "Bu kapsayıcının içeriğini açma desteği yok; tam tarama sonucu verilemedi.", sw.Elapsed));
                }

                if (sha256 == "VIRUS_INFECTED_OS_BLOCKED")
                {
                    var osFinding = new SecurityFinding
                    {
                        ObjectPath = path,
                        ObjectName = fileInfo.Name,
                        RiskLevel = RiskLevel.ConfirmedMalicious,
                        RiskScore = 100,
                        Category = FindingCategory.KnownMalwareHash,
                        Title = $"🚨 Zararlı Yazılım / EICAR: {fileInfo.Name}",
                        Description = "Dosya işletim sistemi çekirdeği tarafından virüslü olduğu gerekçesiyle kilitlendi (ERROR_VIRUS_INFECTED).",
                        ConfidenceLevel = ConfidenceLevel.High,
                        FirstObserved = DateTime.UtcNow,
                        LastObserved = DateTime.UtcNow,
                        Status = FindingStatus.Active
                    };
                    if (_findingService != null)
                    {
                        await _findingService.AddFindingAsync(osFinding, linkedCts.Token);
                    }
                    fileInfo.Refresh();
                    _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, osFinding, null, false, false, policyRevision);
                    return Classified(FileScanDetailedResult.CreateSuccess(path, osFinding, sw.Elapsed, isFromCache: false, isSignedClean: false));
                }

                cancellationToken.ThrowIfCancellationRequested();

                // 3. Bütünleşik DetectionHub ve PUP/Risk Eşik Değerlendirmesi
                // Kural 27: Yol indirimleri kaldırıldı (isGameDir = false)
                var inspection = await _pupCoordinator.AnalyzeLockedContentDetailedAsync(path, fileInfo, sha256, classification, completedArchiveInspection, scanLock, linkedCts.Token);
                var finding = inspection.Finding;
                if (finding != null && (finding.Status == FindingStatus.Resolved || finding.IsAllowlisted))
                {
                    finding = null;
                }
                fileInfo.Refresh();
                if (inspection.IsComplete)
                    _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, finding, sha256, false, false, policyRevision);
                return Classified(inspection.IsComplete
                    ? FileScanDetailedResult.CreateSuccess(path, finding, sw.Elapsed, isFromCache: false, isSignedClean: false)
                    : FileScanDetailedResult.CreateFailed(path, string.Join("; ", inspection.CoverageLimitations), sw.Elapsed, finding));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Global tarama iptali: İşçiyi ve kuyruğu hemen durdurmak için istisnayı yukarı fırlat
                throw;
            }
            catch (OperationCanceledException)
            {
                // Tekil dosya per-file timeout'a uğradı
                _logger?.LogWarning("Per-file scan timed out for {Path} after {Timeout}s", path, perFileTimeout.TotalSeconds);
                return Classified(FileScanDetailedResult.CreateTimeout(path, sw.Elapsed));
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error scanning file {Path}", path);
                return Classified(FileScanDetailedResult.CreateFailed(path, ex.Message, sw.Elapsed));
            }
        }


}
