using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı dosya geliş analizi ve risk verdikti üretim arayüzü.
    /// </summary>
    public interface IRealTimeVerdictProcessor
    {
        /// <summary>
        /// Belirtilen dosyayı çok aşamalı (Hash, İmza, Entropi, PE, Sezgisel) olarak denetler ve verdikt üretir.
        /// </summary>
        Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default);

        /// <summary>
        /// Süresi dolan (30 dakikadan eski) verdikt önbellek kayıtlarını temizler.
        /// </summary>
        void CleanupCache();
    }

    /// <summary>
    /// Gerçek zamanlı çok aşamalı (Progressive Analysis) dosya denetim ve risk verdikti motoru.
    /// </summary>
    public class RealTimeVerdictProcessor : IRealTimeVerdictProcessor
    {
        private readonly IHashService _hashService;
        private readonly ISignatureVerifier _signatureVerifier;
        private readonly IRiskScoringEngine _riskScoringEngine;
        private readonly IFileHashMatcher? _fileHashMatcher;
        private readonly IReputationService? _reputationService;
        private readonly ILogger? _logger;

        private readonly ConcurrentDictionary<string, (string hash, RealTimeVerdict verdict, RealTimePolicyAction policy, int riskScore, RiskLevel riskLevel, string threatTitle, string threatDesc, DateTime cachedAt)> _verdictCache = new(StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar", 
            ".iso", ".zip", ".rar", ".7z", ".vbe", ".wsf", ".cpl", ".msi", ".com", ".pif", ".txt", ".bin", ".dat"
        };

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            ILogger? logger = null)
            : this(hashService, signatureVerifier, riskScoringEngine, null, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            ILogger? logger = null)
            : this(hashService, signatureVerifier, riskScoringEngine, fileHashMatcher, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            IReputationService? reputationService,
            ILogger? logger = null)
        {
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _riskScoringEngine = riskScoringEngine;
            _fileHashMatcher = fileHashMatcher;
            _reputationService = reputationService;
            _logger = logger;
        }

        public void CleanupCache()
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(30);
            var expiredKeys = _verdictCache.Where(kvp => kvp.Value.cachedAt < cutoff).Select(kvp => kvp.Key).ToList();
            foreach (var key in expiredKeys)
            {
                _verdictCache.TryRemove(key, out _);
            }
        }

        public async Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default)
        {
            var scanStart = DateTime.UtcNow;
            var result = new RealTimeVerdictResult
            {
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                ScanStartTime = scanStart
            };

            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath) || FileScannerService.IsSelfOwnedPath(filePath))
            {
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
                return result;
            }

            var fileExt = Path.GetExtension(filePath);
            if (!string.IsNullOrEmpty(fileExt) && ScanFilterPolicy.SafeMediaExtensions.Contains(fileExt))
            {
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
                return result;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0)
                {
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // STAGE 0: Fast Shared Scan-Cache Lookup (FileHashMatcher)
                if (_fileHashMatcher != null && _fileHashMatcher.TryGetCached(filePath, fileInfo, false, out var cachedFinding))
                {
                    if (cachedFinding == null)
                    {
                        result.Verdict = RealTimeVerdict.Clean;
                        result.RecommendedPolicy = RealTimePolicyAction.Allow;
                        result.RiskScore = 0;
                        result.RiskLevel = RiskLevel.Clean;
                        result.ThreatTitle = "Doğrulanmış Temiz Dosya (Önbellek)";
                        result.ScanEndTime = DateTime.UtcNow;
                        result.VerdictTime = DateTime.UtcNow;
                        return result;
                    }
                }

                var ext = fileInfo.Extension.ToLowerInvariant();

                // STAGE 1: Fast Hash & Signature Database Check
                var sha256 = await _hashService.ComputeSha256Async(filePath, ct);
                result.SHA256 = sha256;

                if (sha256 == "VIRUS_INFECTED_OS_BLOCKED")
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 1.0;
                    result.RiskScore = 100;
                    result.RiskLevel = RiskLevel.ConfirmedMalicious;
                    result.ThreatTitle = "🚨 Zararlı Yazılım: EICAR / Virüslü Tehdit (İşletim Sistemi Engelledi)";
                    result.ThreatDescription = "Dosya işletim sistemi çekirdeği tarafından virüslü olduğu gerekçesiyle kilitlendi (ERROR_VIRUS_INFECTED).";
                    result.Evidences.Add("İşletim Sistemi Seviyesinde Virüs Tespiti (ERROR_VIRUS_INFECTED - 0x800700E1)");
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                const string emptySha = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

                // Cache Lookup (Composite key: SHA256 + FileName to avoid cross-heuristic cache contamination)
                var cacheKey = $"{sha256}::{fileInfo.Name.ToLowerInvariant()}";
                if (!string.IsNullOrEmpty(sha256) && !sha256.Equals(emptySha, StringComparison.OrdinalIgnoreCase) && _verdictCache.TryGetValue(cacheKey, out var cached) && (DateTime.UtcNow - cached.cachedAt).TotalMinutes < 30)
                {
                    result.Verdict = cached.verdict;
                    result.RecommendedPolicy = cached.policy;
                    result.RiskScore = cached.riskScore;
                    result.RiskLevel = cached.riskLevel;
                    result.ThreatTitle = !string.IsNullOrEmpty(cached.threatTitle) ? cached.threatTitle : (result.Verdict == RealTimeVerdict.ConfirmedMalicious ? $"Zararlı Dosya: {fileInfo.Name}" : $"Şüpheli Dosya: {fileInfo.Name}");
                    result.ThreatDescription = cached.threatDesc;
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // Check Known Malware Signatures (EICAR, Ransomware, Droppers, Keyloggers)
                var hashMatch = !string.IsNullOrEmpty(sha256) ? MalwareSignatureDatabase.CheckHash(sha256) : new MalwareSignatureMatch();
                if (hashMatch.IsMatched)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.99;
                    result.RiskScore = hashMatch.SeverityScore;
                    result.RiskLevel = RiskLevel.ConfirmedMalicious;
                    result.ThreatTitle = $"🚨 Zararlı Yazılım: {hashMatch.ThreatName}";
                    result.ThreatDescription = $"Dosya bilinen tehdit veritabanındaki '{hashMatch.ThreatName}' imzasıyla eşleşti.";
                    result.Evidences.Add($"İmza: {hashMatch.ThreatName} ({hashMatch.ThreatCategory})");
                    result.Evidences.Add($"Tespit Metodu: {hashMatch.DetectionMethod}");

                    if (!string.IsNullOrEmpty(sha256)) _verdictCache[cacheKey] = (sha256, result.Verdict, result.RecommendedPolicy, result.RiskScore, result.RiskLevel, result.ThreatTitle, result.ThreatDescription, DateTime.UtcNow);
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // Check Cloud Reputation (Abuse.ch MalwareBazaar) if enabled
                if (!hashMatch.IsMatched && _reputationService != null && _reputationService.IsCloudLookupEnabled && !string.IsNullOrEmpty(sha256))
                {
                    try
                    {
                        var cloudRep = await _reputationService.CheckReputationAsync(sha256, ct);
                        if (cloudRep.IsMalicious)
                        {
                            result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                            result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                            result.Confidence = 0.99;
                            result.RiskScore = cloudRep.Severity > 0 ? cloudRep.Severity : 100;
                            result.RiskLevel = RiskLevel.ConfirmedMalicious;
                            result.ThreatTitle = $"🚨 Bulut Tehdit Tespiti: {cloudRep.ThreatName}";
                            result.ThreatDescription = $"Dosya Abuse.ch MalwareBazaar küresel tehdit veritabanında '{cloudRep.ThreatName}' olarak doğrulandı.";
                            result.Evidences.Add($"Bulut İmzası: {cloudRep.ThreatName} ({cloudRep.MalwareFamily ?? "Malware"})");
                            result.Evidences.Add($"Kaynak: {cloudRep.Source}");

                            if (!string.IsNullOrEmpty(sha256)) _verdictCache[cacheKey] = (sha256, result.Verdict, result.RecommendedPolicy, result.RiskScore, result.RiskLevel, result.ThreatTitle, result.ThreatDescription, DateTime.UtcNow);
                            result.ScanEndTime = DateTime.UtcNow;
                            result.VerdictTime = DateTime.UtcNow;
                            return result;
                        }
                    }
                    catch (Exception)
                    {
                        // Kesintisiz çalışma: Bulut hatası yerel taramayı engellemez
                    }
                }

                // Check Pattern & YARA-like Rules (EICAR, Keyloggers, Mimikatz, ShadowCopy Deletion)
                var patternMatch = await MalwareSignatureDatabase.CheckFileContentPatternsAsync(filePath, ct);
                if (patternMatch.IsMatched)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.95;
                    result.RiskScore = patternMatch.SeverityScore;
                    result.RiskLevel = RiskLevel.ConfirmedMalicious;
                    result.ThreatTitle = $"🚨 Şüpheli Kod Deseni: {patternMatch.ThreatName}";
                    result.ThreatDescription = $"Dosya içeriğinde tehlikeli dropper, exploit veya keylogger kodu tespit edildi.";
                    result.Evidences.Add($"Desen: {patternMatch.ThreatName}");
                    result.Evidences.Add($"Metod: {patternMatch.DetectionMethod}");

                    if (!string.IsNullOrEmpty(sha256)) _verdictCache[cacheKey] = (sha256, result.Verdict, result.RecommendedPolicy, result.RiskScore, result.RiskLevel, result.ThreatTitle, result.ThreatDescription, DateTime.UtcNow);
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // STAGE 2: Digital Signature & Trusted Software Policy (Fast-Path Bypass)
                var sigInfo = await _signatureVerifier.VerifySignatureAsync(filePath, ct);
                var trust = AegisPC.Security.Safety.TrustedSoftwarePolicy.EvaluateTrust(
                    filePath,
                    sigInfo.Publisher,
                    sigInfo.IsSigned,
                    sigInfo.IsValid,
                    PathHelper.IsKnownSafePath(filePath));

                if (trust.IsFullyTrusted)
                {
                    result.Verdict = RealTimeVerdict.Clean;
                    result.RecommendedPolicy = RealTimePolicyAction.Allow;
                    result.RiskScore = 0;
                    result.RiskLevel = RiskLevel.Clean;
                    result.ThreatTitle = $"Doğrulanmış Güvenilir Yayımcı ({sigInfo.Publisher})";
                    result.Evidences.Add(trust.Reason);

                    if (!string.IsNullOrEmpty(sha256))
                    {
                        _verdictCache[cacheKey] = (sha256, RealTimeVerdict.Clean, RealTimePolicyAction.Allow, 0, RiskLevel.Clean, result.ThreatTitle, string.Empty, DateTime.UtcNow);
                    }
                    fileInfo.Refresh();
                    _fileHashMatcher?.SetCache(filePath, fileInfo.Length, fileInfo.LastWriteTimeUtc, null);
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // STAGE 3: Entropy & PE Heuristics
                var entropy = await EntropyCalculator.CalculateEntropyAsync(filePath, ct);
                bool isExe = DangerousExtensions.Contains(ext);
                var peAnalysis = isExe ? PeAnalyzer.Analyze(filePath) : new PeAnalysisResult();

                var fileAnalysis = new FileAnalysisResult
                {
                    FilePath = filePath,
                    FileName = fileInfo.Name,
                    SHA256 = sha256,
                    FileSize = fileInfo.Length,
                    CreatedAt = fileInfo.CreationTimeUtc,
                    ModifiedAt = fileInfo.LastWriteTimeUtc,
                    IsSigned = sigInfo.IsSigned,
                    SignaturePublisher = sigInfo.Publisher,
                    SignatureValid = sigInfo.IsValid,
                    IsExecutable = isExe,
                    ExecutableType = peAnalysis.ExecutableType,
                    Entropy = entropy,
                    IsKnownLocation = PathHelper.IsKnownSafePath(filePath)
                };

                var (score, riskLevel, reasons) = await _riskScoringEngine.CalculateRiskScoreAsync(fileAnalysis, ct);
                result.RiskScore = score;
                result.RiskLevel = riskLevel;
                result.Evidences.AddRange(reasons);

                // 1. Confirmed Malicious / Score >= 85 (High Confidence) -> BlockAndQuarantine
                // 2. High Risk / Score >= 70 (Medium Confidence) -> BlockAndQuarantine (Deterministic Security Enforcement)
                // 3. Suspicious / Score >= 50 (Low Confidence) -> Warn (ALLOW + LOG + USER ALERT, NEVER DELETE)
                // 4. Clean / Unknown -> Allow (NEVER DELETE UNKNOWN)
                // RiskScore >= 85 veya ConfirmedMalicious: Otomatik Karantina
                if (riskLevel >= RiskLevel.ConfirmedMalicious || score >= 85)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.95;
                    result.ThreatTitle = $"🚨 Zararlı Yazılım: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                // RiskScore 60-84 veya HighRisk: Uyarıldı (Olay Merkezine kaydedilir, otomatik karantinaya alınmaz)
                else if (riskLevel >= RiskLevel.HighRisk || score >= 60)
                {
                    result.Verdict = RealTimeVerdict.Suspicious;
                    result.RecommendedPolicy = RealTimePolicyAction.Warn;
                    result.Confidence = 0.65;
                    result.ThreatTitle = $"⚠️ Şüpheli Dosya Uyarısı: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else
                {
                    result.Verdict = RealTimeVerdict.Clean;
                    result.RecommendedPolicy = RealTimePolicyAction.Allow;
                    result.Confidence = 0.90;
                    fileInfo.Refresh();
                    _fileHashMatcher?.SetCache(filePath, fileInfo.Length, fileInfo.LastWriteTimeUtc, null);
                }

                if (!string.IsNullOrEmpty(sha256) && !sha256.Equals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", StringComparison.OrdinalIgnoreCase))
                {
                    _verdictCache[cacheKey] = (sha256, result.Verdict, result.RecommendedPolicy, result.RiskScore, result.RiskLevel, result.ThreatTitle, result.ThreatDescription, DateTime.UtcNow);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Inspection failed for {Path}", filePath);
            }
            finally
            {
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
            }

            return result;
        }
    }
}
