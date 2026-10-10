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
            FileScanDetailedResult Classified(FileScanDetailedResult detailed, bool? inspectionComplete = null)
            {
                detailed.ContentClassification = classification;
                detailed.InspectionComplete = inspectionComplete ??
                    (detailed.Outcome == FileScanOutcome.Success ? true :
                     detailed.Outcome == FileScanOutcome.Timeout || classification?.IsComplete == false ? false : null);
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
                using (ScanStageMeasurements.Measure(ScanStageTiming.Content))
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
                if (sha256 == "VIRUS_INFECTED_OS_BLOCKED")
                    throw new AegisPC.Core.Exceptions.OperatingSystemFileBlockException(AegisPC.Core.Exceptions.OperatingSystemFileBlockKind.ThreatBlocked);

                cancellationToken.ThrowIfCancellationRequested();

                // A positive whole-file hash must not be lost behind a container parser limit.
                bool knownThreat = MalwareSignatureDatabase.CheckHash(sha256).IsMatched || ThreatSignatureDatabase.CheckHash(sha256).IsMatched;
                if (knownThreat)
                {
                    var knownInspection = await _pupCoordinator.AnalyzeLockedContentDetailedAsync(path, fileInfo, sha256, classification, null, scanLock, linkedCts.Token);
                    var knownFinding = knownInspection.Finding;
                    if (knownFinding != null)
                    {
                        if (knownInspection.IsComplete)
                            _hashMatcher.SetCache(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, knownFinding, sha256, false, false, policyRevision);
                        return Classified(knownInspection.IsComplete
                            ? FileScanDetailedResult.CreateSuccess(path, knownFinding, sw.Elapsed)
                            : FileScanDetailedResult.CreateFailed(path, string.Join("; ", knownInspection.CoverageLimitations), sw.Elapsed, knownFinding), knownInspection.IsComplete);
                    }
                }

                if (!knownThreat && (isAllowlisted || isMicrosoftBypassed))
                {
                    // Permission to skip is not inspected clean content and must not be cached as such.
                    return Classified(FileScanDetailedResult.CreateSuccess(path, null, sw.Elapsed, isSignedClean: true), inspectionComplete: false);
                }

                // Route by observed structure, not extension. The common hub combines all
                // member evidence with outer-file evidence, even when archive coverage is partial.
                if (classification.RequiresZipInspection)
                {
                    using (ScanStageMeasurements.Measure(ScanStageTiming.Content))
                        completedArchiveInspection = await _archiveScanner.ScanArchiveAsync(path, linkedCts.Token, contentIdentifiedZip: true);
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
                    : FileScanDetailedResult.CreateFailed(path, string.Join("; ", inspection.CoverageLimitations), sw.Elapsed, finding), inspection.IsComplete);
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
                if (AegisPC.Core.Exceptions.OperatingSystemFileBlockException.TryGetKind(ex, out var block))
                {
                    var unavailable = FileScanDetailedResult.CreateFailed(path,
                        "Windows güvenlik sağlayıcısı erişimi engelledi; Ultron içerik incelemesi tamamlanamadı.", sw.Elapsed);
                    unavailable.OperatingSystemBlock = block;
                    return Classified(unavailable, inspectionComplete: false);
                }
                return Classified(FileScanDetailedResult.CreateFailed(path, ex.Message, sw.Elapsed));
            }
        }


}
