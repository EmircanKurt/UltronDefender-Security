using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Constants;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.Scanning
{
    public class FileScannerService : IFileScanner
    {
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly IAllowlistService _allowlistService;
        private readonly ISecurityFindingService _findingService;
        private readonly IDetectionHub _detectionHub;
        private readonly ArchiveSafetyScanner _archiveScanner;
        private readonly ILogger<FileScannerService>? _logger;
        private const int MaxCacheEntries = 50000;
        private readonly ConcurrentDictionary<string, (long FileSize, DateTime LastWriteTimeUtc, SecurityFinding? Finding)> _scanCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ManualResetEventSlim _pauseEvent = new(true);

        private void SetCacheEntry(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding)
        {
            if (_scanCache.Count >= MaxCacheEntries)
            {
                _scanCache.Clear();
            }
            _scanCache[path] = (fileSize, lastWriteTimeUtc, finding);
        }

        public bool IsPaused => !_pauseEvent.IsSet;

        public void PauseScan()
        {
            _pauseEvent.Reset();
        }

        public void ResumeScan()
        {
            _pauseEvent.Set();
        }

        private static readonly HashSet<string> KnownCandidateExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
            ".hta", ".jar", ".wsf", ".ws", ".wsh", ".cpl", ".msi", ".msc", ".reg", ".com", ".pif",
            ".drv", ".ocx", ".efi", ".zip", ".7z", ".rar", ".iso", ".img", ".tar", ".gz", ".cab",
            ".nupkg", ".apk", ".bin", ".dat", ".tmp", ".txt", ".log", ".ini", ".cfg", ".xml", ".json",
            ".csv", ".md", ".inf", ".htm", ".html", ".lua", ".yml", ".yaml"
        };

        private static readonly HashSet<string> SafeMediaExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tiff",
            ".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a",
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm",
            ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
            ".ttf", ".otf", ".woff", ".woff2"
        };

        public FileScannerService(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IAllowlistService allowlistService,
            ISecurityFindingService findingService,
            IDetectionHub? detectionHub = null,
            ArchiveSafetyScanner? archiveScanner = null,
            ILogger<FileScannerService>? logger = null)
        {
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _riskScoringEngine = riskScoringEngine;
            _allowlistService = allowlistService;
            _findingService = findingService;
            _detectionHub = detectionHub ?? DetectionHubFactory.CreateDefault(hashService, signatureVerifier);
            _archiveScanner = archiveScanner ?? new ArchiveSafetyScanner();
            _logger = logger;
        }

        /// <summary>
        /// Content-Over-Extension: Dosyanın uzantısına veya ilk baytlarındaki PE/Arşiv sihirli baytlarına ("MZ", "PK", vb.) bakarak incelenebilirliğini doğrular.
        /// Güvenli medya ve belge dosyalarını atlayarak gereksiz CPU/Disk harcamasını önler.
        /// </summary>
        public static bool IsInspectableCandidate(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;

            try
            {
                if (!File.Exists(filePath)) return false;

                string ext = Path.GetExtension(filePath);
                
                // 1. Bilinen güvenli medya ve ofis uzantılarını doğrudan atla (Hızlı taramayı yavaşlatmaz)
                if (!string.IsNullOrEmpty(ext) && SafeMediaExtensions.Contains(ext))
                {
                    return false;
                }

                // 2. Yürütülebilir veya komut dosyası uzantısı ise doğrudan adaydır
                if (!string.IsNullOrEmpty(ext) && KnownCandidateExtensions.Contains(ext))
                {
                    return true;
                }

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0 || fileInfo.Length > 200 * 1024 * 1024)
                {
                    return false;
                }

                // 3. Sihirli Bayt (Magic Byte) Denetimi: PE ("MZ"), ZIP ("PK"), 7z, RAR, Shebang ("#!")
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 16);
                byte[] header = new byte[4];
                int read = fs.Read(header, 0, 4);

                if (read >= 2)
                {
                    // MZ (Portable Executable - Windows PE32 / PE64 / DLL / SYS)
                    if (header[0] == 0x4D && header[1] == 0x5A) return true;

                    // PK (ZIP, JAR, APK, OpenXML)
                    if (header[0] == 0x50 && header[1] == 0x4B) return true;

                    // Shebang (#!) script
                    if (header[0] == 0x23 && header[1] == 0x21) return true;

                    if (read >= 4)
                    {
                        // 7z (37 7A BC AF)
                        if (header[0] == 0x37 && header[1] == 0x7A && header[2] == 0xBC && header[3] == 0xAF) return true;

                        // RAR (52 61 72 21)
                        if (header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && header[3] == 0x21) return true;
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        public async Task<SecurityFinding?> ScanFileAsync(string path, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(path)) return null;

            try
            {
                var fileInfo = new FileInfo(path);

                // Multi-Tier Caching: Skip deep 13-detector re-scan if clean and unchanged
                if (_scanCache.TryGetValue(path, out var cached))
                {
                    if (cached.FileSize == fileInfo.Length && cached.LastWriteTimeUtc == fileInfo.LastWriteTimeUtc)
                    {
                        return cached.Finding;
                    }
                }

                var ext = fileInfo.Extension.ToLowerInvariant();

                // 1. Arşiv Dosyası Güvenlik Taraması (Zip bomb, path traversal, nested payload)
                if (ext == ".zip" || ext == ".jar" || ext == ".nupkg" || ext == ".apk")
                {
                    var archiveResult = await _archiveScanner.ScanArchiveAsync(path, cancellationToken);
                    if (archiveResult.Findings.Count > 0)
                    {
                        var topFinding = archiveResult.Findings.OrderByDescending(f => f.RiskScore).First();
                        await _findingService.AddFindingAsync(topFinding, cancellationToken);
                        SetCacheEntry(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, topFinding);
                        return topFinding;
                    }
                }

                // 2. SHA256 Hesaplama & Güvenli Beyaz Liste (Allowlist)
                var sha256 = await _hashService.ComputeSha256Async(path, cancellationToken);
                if (!string.IsNullOrEmpty(sha256) && await _allowlistService.IsAllowlistedAsync(sha256, cancellationToken))
                {
                    return null; // Beyaz listede güvenli onaylı
                }

                bool isGameDir = PathHelper.IsGameOrRepackDirectory(path);
                if (isGameDir)
                {
                    // Non-executables in game directories are safe game resources (levels, lua scripts, licenses, json, etc.)
                    if (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" && ext != ".ps1")
                    {
                        return null;
                    }
                }

                // 3. Tekil ve Bütünleşik DetectionHub ile 13 Modüler Dedektör Üzerinden Analiz
                var context = new DetectionContext
                {
                    FilePath = path,
                    SHA256 = sha256,
                    FileSize = fileInfo.Length,
                    ProcessId = 0,
                    CorrelationId = Guid.NewGuid().ToString("N")
                };

                var detectionResult = await _detectionHub.EvaluateAsync(context, cancellationToken);

                // 4. Eşik Değeri ve Risk Kararı Haritalaması (Oyun klasörlerinde güvenli emülatörler için 85 eşik, genel sistemde 50 eşik)
                int minThreshold = isGameDir ? 85 : 50;
                bool hasExplicitSignature = detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticSignature);

                if ((detectionResult.Verdict >= DetectionVerdict.Suspicious && detectionResult.RiskScore >= minThreshold) || hasExplicitSignature)
                {
                    RiskLevel riskLevel = detectionResult.RiskScore switch
                    {
                        >= 85 => RiskLevel.ConfirmedMalicious,
                        >= 70 => RiskLevel.HighRisk,
                        _ => RiskLevel.Suspicious
                    };

                    var reasons = detectionResult.Evidences
                        .Select(e => $"[{e.Category}] {e.Description} (+{e.ScoreContribution})")
                        .ToList();

                    if (reasons.Count == 0 && !string.IsNullOrEmpty(detectionResult.ThreatTitle))
                    {
                        reasons.Add(detectionResult.ThreatTitle);
                    }

                    FindingCategory findingCat = FindingCategory.SuspiciousLocation;
                    if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticSignature))
                        findingCat = FindingCategory.KnownMalwareHash;
                    else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticPeStructure || e.Category == EvidenceCategory.StaticApi))
                        findingCat = FindingCategory.MalwareSuspicion;
                    else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.ScriptHeuristic))
                        findingCat = FindingCategory.SuspiciousScript;
                    else if (detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.Persistence))
                        findingCat = FindingCategory.SuspiciousPersistence;

                    string threatTitle = !string.IsNullOrEmpty(detectionResult.ThreatTitle)
                        ? detectionResult.ThreatTitle
                        : (riskLevel == RiskLevel.ConfirmedMalicious ? $"Zararlı Yazılım Tespit Edildi: {fileInfo.Name}" : $"Yüksek Riskli Şüpheli Dosya: {fileInfo.Name}");

                    var finding = new SecurityFinding
                    {
                        ObjectPath = path,
                        ObjectName = fileInfo.Name,
                        SHA256 = sha256,
                        RiskLevel = riskLevel,
                        RiskScore = detectionResult.RiskScore,
                        Category = findingCat,
                        Title = threatTitle,
                        Description = string.Join(" | ", detectionResult.Evidences.Take(2).Select(e => e.Description)),
                        RiskReasons = reasons,
                        ConfidenceLevel = detectionResult.OverallConfidence == EvidenceConfidence.Absolute || detectionResult.OverallConfidence == EvidenceConfidence.High
                            ? ConfidenceLevel.High
                            : ConfidenceLevel.Medium,
                        FirstObserved = DateTime.UtcNow,
                        LastObserved = DateTime.UtcNow,
                        Status = FindingStatus.Active
                    };

                    await _findingService.AddFindingAsync(finding, cancellationToken);
                    SetCacheEntry(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, finding);
                    return finding;
                }

                SetCacheEntry(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, null);
                return null;
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Error scanning file {Path}", path);
                return null;
            }
        }

        public async Task<ScanResult> ScanDirectoryAsync(
            string path,
            ScanType scanType,
            IProgress<ScanProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var findings = new ConcurrentBag<SecurityFinding>();

            int totalFiles = 0;
            int scannedFiles = 0;
            int skippedFiles = 0;
            bool isProducerDone = false;
            int maxReportedPercent = 0;

            var lastReport = Stopwatch.StartNew();
            var progressLock = new object();

            void ReportProgress(string currentFile, int? explicitPercent = null, bool force = false)
            {
                if (progress == null) return;

                lock (progressLock)
                {
                    if (!force && lastReport.ElapsedMilliseconds < 120)
                    {
                        return;
                    }
                    lastReport.Restart();

                    int currentTotal = Volatile.Read(ref totalFiles);
                    int currentScanned = Volatile.Read(ref scannedFiles);
                    int currentSkipped = Volatile.Read(ref skippedFiles);
                    bool producerDone = Volatile.Read(ref isProducerDone);

                    int calculatedPercent;
                    if (explicitPercent.HasValue)
                    {
                        calculatedPercent = explicitPercent.Value;
                    }
                    else if (producerDone && currentTotal > 0)
                    {
                        double ratio = (double)currentScanned / currentTotal;
                        calculatedPercent = 15 + (int)(ratio * 84.0);
                    }
                    else
                    {
                        if (currentScanned == 0)
                        {
                            calculatedPercent = 12;
                        }
                        else
                        {
                            double ratio = (double)currentScanned / Math.Max(currentTotal, currentScanned + 60);
                            calculatedPercent = 12 + (int)(ratio * 48.0);
                        }
                    }

                    calculatedPercent = Math.Clamp(calculatedPercent, 0, 99);
                    int reportedPercent = Math.Max(maxReportedPercent, calculatedPercent);
                    maxReportedPercent = reportedPercent;

                    progress.Report(new ScanProgress
                    {
                        ScanType = scanType,
                        TotalFiles = Math.Max(currentTotal, currentScanned),
                        ScannedFiles = currentScanned,
                        SkippedFiles = currentSkipped,
                        FindingsCount = findings.Count,
                        CurrentFile = currentFile,
                        ProgressPercent = reportedPercent,
                        IsCompleted = false
                    });
                }
            }

            // ══════════════════════════════════════════════════════════════
            // STAGE 1: MICROSOFT MRT (MSRT) REMEDIATION SCAN (0% - 12%)
            // ══════════════════════════════════════════════════════════════
            if (scanType == ScanType.Full || scanType == ScanType.Quick)
            {
                int mrtStep = 0;
                var mrtReporter = new Progress<string>(phase =>
                {
                    mrtStep++;
                    int mrtPercent = Math.Min(12, mrtStep * 2);
                    ReportProgress(phase, mrtPercent, force: true);
                });

                var mrtFindings = await MsrtRemediationEngine.RunMsrtDeepScanAsync(mrtReporter, cancellationToken);
                foreach (var f in mrtFindings)
                {
                    findings.Add(f);
                    await _findingService.AddFindingAsync(f, cancellationToken);
                }
            }

            // ══════════════════════════════════════════════════════════════
            // STAGE 2: ASYNC FILE STREAMING & CONCURRENT SCANNING
            // ══════════════════════════════════════════════════════════════
            var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(5000)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleWriter = true,
                SingleReader = false
            });

            var producerTask = Task.Run(async () =>
            {
                var queuedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                async Task TryQueueFileAsync(string? filePath)
                {
                    if (string.IsNullOrWhiteSpace(filePath) || cancellationToken.IsCancellationRequested) return;

                    try
                    {
                        if (File.Exists(filePath) && IsInspectableCandidate(filePath))
                        {
                            if (queuedPaths.Add(filePath))
                            {
                                Interlocked.Increment(ref totalFiles);
                                await channel.Writer.WriteAsync(filePath, cancellationToken);
                            }
                        }
                    }
                    catch { }
                }

                async Task EnumerateDirectorySafelyAsync(string dirPath, bool recursive = true)
                {
                    if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath) || cancellationToken.IsCancellationRequested) return;

                    var dirQueue = new Queue<string>();
                    dirQueue.Enqueue(dirPath);

                    while (dirQueue.Count > 0 && !cancellationToken.IsCancellationRequested)
                    {
                        _pauseEvent.Wait(cancellationToken);
                        string currentDir = dirQueue.Dequeue();

                        try
                        {
                            // 1. Dizin içindeki dosyaları kuyruğa ekle
                            foreach (var file in Directory.EnumerateFiles(currentDir))
                            {
                                if (cancellationToken.IsCancellationRequested) break;
                                _pauseEvent.Wait(cancellationToken);
                                await TryQueueFileAsync(file);
                            }

                            // 2. Alt dizinleri kuyruğa ekle (Junction / ReparsePoint atlayarak sonsuz döngüyü engelle)
                            if (recursive)
                            {
                                foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                                {
                                    if (cancellationToken.IsCancellationRequested) break;

                                    try
                                    {
                                        var dirInfo = new DirectoryInfo(subDir);
                                        if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                                        if (dirInfo.Name.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
                                            dirInfo.Name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)) continue;

                                        dirQueue.Enqueue(subDir);
                                    }
                                    catch { }
                                }
                            }
                        }
                        catch { } // Bir dizindeki erişim hatası diğer dizinleri ASLA durdurmaz!
                    }
                }

                try
                {
                    if (scanType == ScanType.Full)
                    {
                        // ───────────────────────────────────────────────────────
                        // TAM DİSK TARAMASI: TÜM SABİT SÜRÜCÜLER VE KULLANICI DİZİNLERİ
                        // ───────────────────────────────────────────────────────
                        ReportProgress("Öncelikli Kullanıcı Alanları indeksleniyor...");
                        var highPriorityDirs = new List<string>
                        {
                            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                            KnownPaths.Downloads,
                            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                            KnownPaths.UserStartup,
                            KnownPaths.CommonStartup,
                            KnownPaths.Temp,
                            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")
                        };

                        foreach (var hpDir in highPriorityDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            await EnumerateDirectorySafelyAsync(hpDir, recursive: true);
                        }

                        var allDrives = DriveInfo.GetDrives()
                            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                            .Select(d => d.RootDirectory.FullName)
                            .ToList();

                        foreach (var driveRoot in allDrives)
                        {
                            if (cancellationToken.IsCancellationRequested) break;
                            ReportProgress($"Disk taranıyor: {driveRoot}");
                            await EnumerateDirectorySafelyAsync(driveRoot, recursive: true);
                        }
                    }
                    else if (scanType == ScanType.Quick)
                    {
                        // ───────────────────────────────────────────────────────
                        // HIZLI TARAMA: AKTİF BELLEK SÜREÇLERİ, BAŞLANGIÇ & KRİTİK SİSTEM DİZİNLERİ
                        // (Kullanıcı medya dosyalarını taramadan yıldırım hızında tamamlanır)
                        // ───────────────────────────────────────────────────────
                        ReportProgress("Hızlı Tarama: Aktif Bellek Süreçleri ve Modülleri taranıyor...");
                        try
                        {
                            var activeProcesses = Process.GetProcesses();
                            foreach (var proc in activeProcesses)
                            {
                                if (cancellationToken.IsCancellationRequested) break;
                                if (proc.Id <= 4) continue;

                                try
                                {
                                    string? mainModule = proc.MainModule?.FileName;
                                    if (!string.IsNullOrEmpty(mainModule))
                                    {
                                        await TryQueueFileAsync(mainModule);
                                    }

                                    foreach (ProcessModule mod in proc.Modules)
                                    {
                                        if (!string.IsNullOrEmpty(mod.FileName))
                                        {
                                            await TryQueueFileAsync(mod.FileName);
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }

                        // Başlangıç ve Otomatik Çalıştırma Klasörleri
                        ReportProgress("Başlangıç ve Otomatik Çalıştırma Dizinleri taranıyor...");
                        await EnumerateDirectorySafelyAsync(KnownPaths.UserStartup, true);
                        await EnumerateDirectorySafelyAsync(KnownPaths.CommonStartup, true);

                        // Geçici Dizinler (Yürütülebilir dosyalar)
                        await EnumerateDirectorySafelyAsync(KnownPaths.Temp, false);
                        await EnumerateDirectorySafelyAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), false);

                        // Masaüstü (Yalnızca kök seviye dosyalar)
                        await EnumerateDirectorySafelyAsync(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), false);

                        // Sistem Sürücüleri ve System32
                        ReportProgress("Kritik Sistem Sürücüleri taranıyor...");
                        await EnumerateDirectorySafelyAsync(Path.Combine(KnownPaths.System32, "drivers"), true);
                        await EnumerateDirectorySafelyAsync(KnownPaths.System32, false);

                        string sysWow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
                        if (Directory.Exists(sysWow64))
                        {
                            await EnumerateDirectorySafelyAsync(sysWow64, false);
                        }
                    }
                    else if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                    {
                        await EnumerateDirectorySafelyAsync(path, true);
                    }
                }
                finally
                {
                    isProducerDone = true;
                    channel.Writer.Complete();
                }
            }, cancellationToken);

            // Consumer Tasks: Paralel tarama işçileri
            int concurrency = Math.Clamp(Environment.ProcessorCount * 2, 4, 16);
            var workerTasks = new List<Task>();

            for (int i = 0; i < concurrency; i++)
            {
                workerTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        await foreach (var filePath in channel.Reader.ReadAllAsync(cancellationToken))
                        {
                            try
                            {
                                _pauseEvent.Wait(cancellationToken);
                                var finding = await ScanFileAsync(filePath, cancellationToken);
                                if (finding != null)
                                {
                                    findings.Add(finding);
                                }
                            }
                            catch
                            {
                                Interlocked.Increment(ref skippedFiles);
                            }
                            finally
                            {
                                Interlocked.Increment(ref scannedFiles);
                                ReportProgress(filePath);
                            }
                        }
                    }
                    catch (OperationCanceledException) { }
                }, cancellationToken));
            }

            await Task.WhenAll(workerTasks.Concat(new[] { producerTask }));
            stopwatch.Stop();

            int finalTotal = Volatile.Read(ref totalFiles);
            int finalScanned = Volatile.Read(ref scannedFiles);
            int finalSkipped = Volatile.Read(ref skippedFiles);

            progress?.Report(new ScanProgress
            {
                ScanType = scanType,
                TotalFiles = finalTotal,
                ScannedFiles = finalScanned,
                SkippedFiles = finalSkipped,
                FindingsCount = findings.Count,
                CurrentFile = "Tamamlandı",
                ProgressPercent = 100,
                IsCompleted = true
            });

            return new ScanResult
            {
                ScanType = scanType,
                StartedAt = DateTime.UtcNow.Subtract(stopwatch.Elapsed),
                CompletedAt = DateTime.UtcNow,
                Status = cancellationToken.IsCancellationRequested ? ScanStatus.Cancelled : ScanStatus.Completed,
                TotalFiles = finalTotal,
                ScannedFiles = finalScanned,
                SkippedFiles = finalSkipped,
                CustomPath = path,
                ElapsedMs = stopwatch.ElapsedMilliseconds,
                Findings = findings.ToList()
            };
        }
    }
}
