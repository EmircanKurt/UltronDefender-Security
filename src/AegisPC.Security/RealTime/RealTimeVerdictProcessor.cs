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
        {
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _riskScoringEngine = riskScoringEngine;
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

            try
            {
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0)
                {
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
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

                // STAGE 2: Digital Signature & Trusted Publisher
                var sigInfo = await _signatureVerifier.VerifySignatureAsync(filePath, ct);
                if (sigInfo.IsValid && sigInfo.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true && PathHelper.IsKnownSafePath(filePath))
                {
                    if (!string.IsNullOrEmpty(sha256)) _verdictCache[cacheKey] = (sha256, RealTimeVerdict.Clean, RealTimePolicyAction.Allow, 0, RiskLevel.Clean, "Güvenilir Microsoft İmzalı Dosya", string.Empty, DateTime.UtcNow);
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

                // POLICY MATRIX WITH GAMER / REPACK SAFE SHIELD:
                bool isGameOrRepack = PathHelper.IsGameOrRepackDirectory(filePath) || GameCrackClassifier.IsGameCrackOrEmulator(filePath);

                // 1. Confirmed Malicious / Score >= 85 (High Confidence) -> BlockAndQuarantine
                // 2. High Risk / Score >= 70 (Medium Confidence) -> BlockAndQuarantine (Oyun/Crack dosyaları için muaf tutulur)
                // 3. Suspicious / Score >= 40 (Low Confidence) -> Warn (ALLOW + LOG + USER ALERT, NEVER DELETE)
                // 4. Clean / Unknown / Game Crack -> Allow (NEVER DELETE UNKNOWN)
                if (riskLevel >= RiskLevel.ConfirmedMalicious || score >= 85)
                {
                    result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.95;
                    result.ThreatTitle = $"🚨 Zararlı Yazılım: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else if (!isGameOrRepack && (riskLevel >= RiskLevel.HighRisk || score >= 70))
                {
                    result.Verdict = RealTimeVerdict.Suspicious;
                    result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
                    result.Confidence = 0.80;
                    result.ThreatTitle = $"⚠️ Yüksek Riskli Dosya: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else if (score >= 50 && !isGameOrRepack)
                {
                    result.Verdict = RealTimeVerdict.Suspicious;
                    result.RecommendedPolicy = RealTimePolicyAction.Warn;
                    result.Confidence = 0.50;
                    result.ThreatTitle = $"⚠️ Şüpheli Dosya Uyarısı: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else
                {
                    result.Verdict = RealTimeVerdict.Clean;
                    result.RecommendedPolicy = RealTimePolicyAction.Allow;
                    result.Confidence = 0.90;
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
