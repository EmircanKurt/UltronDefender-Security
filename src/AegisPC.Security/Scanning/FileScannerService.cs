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
        private const int MaxCacheEntries = 10000;
        private readonly ConcurrentDictionary<string, (long FileSize, DateTime LastWriteTimeUtc, SecurityFinding? Finding)> _scanCache = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<string> _cacheKeyQueue = new();
        private readonly ManualResetEventSlim _pauseEvent = new(true);

        private void SetCacheEntry(string path, long fileSize, DateTime lastWriteTimeUtc, SecurityFinding? finding)
        {
            if (_scanCache.Count >= MaxCacheEntries)
            {
                // Sıfır tahsisli FIFO tahliye (Snapshot almadan mikrosaniyede temizlik)
                while (_scanCache.Count >= (MaxCacheEntries - 1000) && _cacheKeyQueue.TryDequeue(out var oldKey))
                {
                    _scanCache.TryRemove(oldKey, out _);
                }
            }
            _scanCache[path] = (fileSize, lastWriteTimeUtc, finding);
            _cacheKeyQueue.Enqueue(path);
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
            ".nupkg", ".apk", ".bin", ".dat", ".tmp"
        };

        private static readonly HashSet<string> SafeMediaExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            // Medya ve Ses Dosyaları (Yürütülemez Veri)
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tiff", ".tga", ".psd",
            ".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a", ".wma", ".opus", ".mid", ".midi",
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv", ".m4v", ".3gp",
            // Belgeler ve Yazı Tipleri
            ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".doc", ".xls", ".ppt",
            ".ttf", ".otf", ".woff", ".woff2", ".eot", ".fon",
            // 3D Modeller, Dokular ve Oyun Varlıkları (Tamamen veri / render dosyaları)
            ".dae", ".dds", ".obj", ".fbx", ".blend", ".3ds", ".max", ".gltf", ".glb", ".mtl", ".mat",
            ".prefab", ".asset", ".anim", ".mesh", ".unityweb", ".pck", ".bsp", ".wad", ".pak",
            ".pc", ".jbeam", ".cda", ".bik", ".bk2",
            // Metin, Yapılandırma ve Veri Dosyaları (Yürütülemez — 2 Milyon Dosyada Mikro-saniye Atlama)
            ".txt", ".log", ".ini", ".cfg", ".conf", ".xml", ".json", ".csv", ".tsv", ".md", ".inf",
            ".htm", ".html", ".css", ".scss", ".sass", ".less", ".map", ".sql", ".sqlite", ".db-shm",
            ".db-wal", ".yml", ".yaml", ".toml", ".properties", ".nfo", ".diz", ".mo", ".po", ".pot",
            ".cache", ".idx", ".dict", ".sub", ".srt", ".vtt", ".ass"
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

                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                
                // 1. Bilinen güvenli medya, ofis ve belge uzantılarını doğrudan atla (CPU/RAM harcamaz)
                if (!string.IsNullOrEmpty(ext) && SafeMediaExtensions.Contains(ext))
                {
                    return false;
                }

                // 2. Oyun ve Mod Klasörü Koruması: Oyun kaynakları (.zip, .bin, .dat, .pak, .dds, .dae) virüs değildir ve devasadır
                bool isGame = PathHelper.IsGameOrRepackDirectory(filePath) || GameCrackClassifier.IsGameCrackOrEmulator(filePath);
                if (isGame && (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" && ext != ".cmd" && ext != ".ps1"))
                {
                    return false;
                }

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0) return false;

                // 3. 100 MB'dan büyük dosyaları tarama (Oyun repacki, büyük video, ISO, VM disk vb. CPU/RAM patlamasını önler)
                if (fileInfo.Length > 100 * 1024 * 1024)
                {
                    return false;
                }

                // 4. Yürütülebilir veya komut dosyası uzantısı ise doğrudan adaydır
                if (!string.IsNullOrEmpty(ext) && KnownCandidateExtensions.Contains(ext))
                {
                    return true;
                }

                // 5. Sihirli Bayt (Magic Byte) Denetimi: PE ("MZ"), ZIP ("PK"), 7z, RAR, Shebang ("#!")
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 16);
                Span<byte> header = stackalloc byte[4];
                int read = fs.Read(header);

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
                if (fileInfo.Length == 0 || fileInfo.Length > 100 * 1024 * 1024) return null;

                var ext = fileInfo.Extension.ToLowerInvariant();
                bool isGameDir = PathHelper.IsGameOrRepackDirectory(path) || GameCrackClassifier.IsGameCrackOrEmulator(path);

                // Multi-Tier Caching: Skip deep 13-detector re-scan if clean and unchanged
                if (_scanCache.TryGetValue(path, out var cached))
                {
                    if (cached.FileSize == fileInfo.Length && cached.LastWriteTimeUtc == fileInfo.LastWriteTimeUtc)
                    {
                        // Eski sahte tespitleri (oyun, mod, zip) önbellekten dönmeyip temizce değerlendir
                        if (cached.Finding == null || (!isGameDir && ext != ".zip"))
                        {
                            return cached.Finding;
                        }
                    }
                }

                // 1. Oyun Klasörü Kontrolü — Güvenli oyun modları ve kaynaklarını (BeamNG zip modları, seviyeler, dokular) atla
                if (isGameDir)
                {
                    if (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" && ext != ".ps1")
                    {
                        return null;
                    }
                }

                // 2. Arşiv Dosyası Güvenlik Taraması (Zip bomb, path traversal, nested payload)
                if (ext == ".zip" || ext == ".jar" || ext == ".nupkg" || ext == ".apk")
                {
                    if (!isGameDir)
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
                }

                // 3. SHA256 Hesaplama & Güvenli Beyaz Liste (Allowlist)
                var sha256 = await _hashService.ComputeSha256Async(path, cancellationToken);
                if (!string.IsNullOrEmpty(sha256) && await _allowlistService.IsAllowlistedAsync(sha256, cancellationToken))
                {
                    SetCacheEntry(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, null);
                    return null; // Beyaz listede güvenli onaylı
                }

                // 3.5. Fast-Path Microsoft / WHQL Dijital İmza Denetimi (Windows, System32 ve Program Files altındaki geçerli imzalı dosyalar için derin analizi atla)
                if (PathHelper.IsSystemPath(path) ||
                    path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase))
                {
                    var sig = await _signatureVerifier.VerifySignatureAsync(path, cancellationToken);
                    if (sig.IsSigned && sig.IsValid && !string.IsNullOrEmpty(sig.Publisher) && (
                        sig.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                        sig.Publisher.Contains("Windows", StringComparison.OrdinalIgnoreCase) ||
                        sig.Publisher.Contains("Google", StringComparison.OrdinalIgnoreCase)))
                    {
                        SetCacheEntry(path, fileInfo.Length, fileInfo.LastWriteTimeUtc, null);
                        return null;
                    }
                }

                // 4. Tekil ve Bütünleşik DetectionHub ile 13 Modüler Dedektör Üzerinden Analiz
                var context = new DetectionContext
                {
                    FilePath = path,
                    SHA256 = sha256,
                    FileSize = fileInfo.Length,
                    ProcessId = 0,
                    CorrelationId = Guid.NewGuid().ToString("N")
                };

                var detectionResult = await _detectionHub.EvaluateAsync(context, cancellationToken);

                // 5. Eşik Değeri ve Risk Kararı Haritalaması (Oyun klasörlerinde güvenli emülatörler için 85 eşik, genel sistemde 50 eşik)
                int minThreshold = isGameDir ? 85 : 50;
                bool hasExplicitSignature = detectionResult.Evidences.Any(e => e.Category == EvidenceCategory.StaticSignature && e.ScoreContribution >= 80);

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

        private static readonly HashSet<string> ExcludedDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "$Recycle.Bin",
            "System Volume Information",
            "WinSxS",
            "Servicing",
            "SoftwareDistribution",
            "assembly",
            "Microsoft.NET",
            "Installer",
            "DriverStore",
            "SystemApps",
            "Prefetch",
            "Panther",
            "rescache",
            "Fonts",
            "DeliveryOptimization",
            "$Windows.~BT",
            "$WinREAgent",
            "Config.Msi",
            "Recovery",
            ".git",
            ".vs",
            ".cache",
            "node_modules",
            "Package Cache",
            "AegisPC_BrowserStress_Tests",
            "AegisLabSuite"
        };

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
            var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(8192)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleWriter = true,
                SingleReader = false
            });

            var producerTask = Task.Run(async () =>
            {
                var queuedPaths = scanType != ScanType.Full ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) : null;

                async Task TryQueueFileAsync(string? filePath)
                {
                    if (string.IsNullOrWhiteSpace(filePath) || cancellationToken.IsCancellationRequested) return;

                    try
                    {
                        if (queuedPaths == null || queuedPaths.Add(filePath))
                        {
                            Interlocked.Increment(ref totalFiles);

                            string ext = Path.GetExtension(filePath);

                            // Fast-Path 1: Medya, doku, metin ve statik asset dosyalarını anında atla (0 disk syscall, mikro-saniye)
                            if (!string.IsNullOrEmpty(ext) && SafeMediaExtensions.Contains(ext))
                            {
                                Interlocked.Increment(ref scannedFiles);
                                return;
                            }

                            // Fast-Path 2: Oyun ve Mod Klasörü Koruması (Yalnızca yürütülebilir ikili dosyaları tara)
                            bool isGame = PathHelper.IsGameOrRepackDirectory(filePath) || GameCrackClassifier.IsGameCrackOrEmulator(filePath);
                            if (isGame && (ext != ".exe" && ext != ".dll" && ext != ".scr" && ext != ".bat" && ext != ".cmd" && ext != ".ps1"))
                            {
                                Interlocked.Increment(ref scannedFiles);
                                return;
                            }

                            // Fast-Path 3: Yürütülebilir / Script / Arşiv / İnceleme adaylarını paralel işçi kuyruğuna yaz
                            await channel.Writer.WriteAsync(filePath, cancellationToken);
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
                                bool isWindowsRoot = currentDir.Equals(KnownPaths.WindowsDir, StringComparison.OrdinalIgnoreCase);

                                foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                                {
                                    if (cancellationToken.IsCancellationRequested) break;

                                    try
                                    {
                                        var dirInfo = new DirectoryInfo(subDir);
                                        if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0) continue;

                                        // Windows kök dizinindeyken yalnızca tehdit barındırabilecek kritik çalışma alanlarını kuyruğa ekle
                                        if (isWindowsRoot)
                                        {
                                            if (!dirInfo.Name.Equals("System32", StringComparison.OrdinalIgnoreCase) &&
                                                !dirInfo.Name.Equals("SysWOW64", StringComparison.OrdinalIgnoreCase) &&
                                                !dirInfo.Name.Equals("Temp", StringComparison.OrdinalIgnoreCase))
                                            {
                                                continue;
                                            }
                                        }

                                        if (ExcludedDirectoryNames.Contains(dirInfo.Name) ||
                                            dirInfo.Name.StartsWith("AegisLabSuite_", StringComparison.OrdinalIgnoreCase) ||
                                            dirInfo.Name.StartsWith("AegisPC_", StringComparison.OrdinalIgnoreCase)) continue;

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
                        // TAM DİSK TARAMASI: TÜM SABİT SÜRÜCÜLER TEK SEFERDE TEMİZCE TARANIR
                        // (Milyonlarca dosya yolu bellekte tutulmaz, her dosya tekil taranır)
                        // ───────────────────────────────────────────────────────
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

                        // Windows Registry Autoruns (HKCU & HKLM Run anahtarları)
                        try
                        {
                            using var cuKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                            if (cuKey != null)
                            {
                                foreach (var valName in cuKey.GetValueNames())
                                {
                                    var rawVal = cuKey.GetValue(valName)?.ToString();
                                    if (!string.IsNullOrEmpty(rawVal))
                                    {
                                        var cleanPath = PathHelper.ExtractExecutablePath(rawVal);
                                        if (File.Exists(cleanPath)) await TryQueueFileAsync(cleanPath);
                                    }
                                }
                            }

                            using var lmKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                            if (lmKey != null)
                            {
                                foreach (var valName in lmKey.GetValueNames())
                                {
                                    var rawVal = lmKey.GetValue(valName)?.ToString();
                                    if (!string.IsNullOrEmpty(rawVal))
                                    {
                                        var cleanPath = PathHelper.ExtractExecutablePath(rawVal);
                                        if (File.Exists(cleanPath)) await TryQueueFileAsync(cleanPath);
                                    }
                                }
                            }
                        }
                        catch { }

                        // İndirilenler & Masaüstü (En yaygın indirme bulaşma noktaları)
                        await EnumerateDirectorySafelyAsync(KnownPaths.Downloads, false);
                        await EnumerateDirectorySafelyAsync(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), false);

                        // Geçici Dizinler (%TEMP% ve Windows\Temp)
                        await EnumerateDirectorySafelyAsync(KnownPaths.Temp, false);
                        await EnumerateDirectorySafelyAsync(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), false);

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

            // Consumer Tasks: Paralel tarama işçileri (HDD/SSD Donanım Duyarlı)
            // SSD/NVMe: Çok çekirdekli paralellik (ProcessorCount * 0.75)
            // HDD: Mekanik kafa atlamasını (head thrashing) engelleyen sıralı 2 iş parçacığı
            bool isSsd = DiskHardwareHelper.IsSolidStateDrive(path);
            int concurrency = isSsd
                ? Math.Clamp((int)Math.Ceiling(Environment.ProcessorCount * 0.75), 2, 8)
                : 2;
            var workerTasks = new List<Task>();

            for (int i = 0; i < concurrency; i++)
            {
                workerTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
                        int fileProcessCounter = 0;

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
                                int currentScanned = Interlocked.Increment(ref scannedFiles);
                                fileProcessCounter++;

                                // Dengeli CPU Yönetimi: Her 50 dosyada bir sisteme kooperatif nefes aldırma
                                if ((fileProcessCounter % 50) == 0)
                                {
                                    await Task.Yield();
                                }

                                // Periyodik hafif Gen0/Gen1 temizliği (Stop-The-World engellenir)
                                if ((currentScanned % 1000) == 0)
                                {
                                    GC.Collect(0, GCCollectionMode.Optimized, false, false);
                                }

                                ReportProgress(filePath);
                            }
                        }
                    }
                    catch (OperationCanceledException) { }
                }, cancellationToken));
            }

            workerTasks.Add(producerTask);
            await Task.WhenAll(workerTasks);
            stopwatch.Stop();

            // Tarama tamamlandığında çalışan tüm Gen2/LOH birikimini eksiksiz serbest bırak
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);

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
