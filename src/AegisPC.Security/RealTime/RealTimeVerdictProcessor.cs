using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Contracts.Detection;
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
        private readonly IExclusionService? _exclusionService;
        private readonly ILogger? _logger;
        private readonly IDetectionHub? _detectionHub;


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
            : this(hashService, signatureVerifier, riskScoringEngine, null, null, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            ILogger? logger = null)
            : this(hashService, signatureVerifier, riskScoringEngine, fileHashMatcher, null, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            IReputationService? reputationService,
            ILogger? logger = null)
            : this(hashService, signatureVerifier, riskScoringEngine, fileHashMatcher, reputationService, null, logger)
        {
        }

        public RealTimeVerdictProcessor(
            IHashService hashService,
            ISignatureVerifier signatureVerifier,
            IRiskScoringEngine riskScoringEngine,
            IFileHashMatcher? fileHashMatcher,
            IReputationService? reputationService,
            IExclusionService? exclusionService,
            ILogger? logger = null,
            IDetectionHub? detectionHub = null)
        {
            _hashService = hashService;
            _signatureVerifier = signatureVerifier;
            _riskScoringEngine = riskScoringEngine;
            _fileHashMatcher = fileHashMatcher;
            _reputationService = reputationService;
            _exclusionService = exclusionService;
            _logger = logger;
            _detectionHub = detectionHub;
        }

        /// <summary>Compatibility hook; unversioned local verdict caching is disabled.</summary>
        public void CleanupCache() { }

        public async Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            var scanStart = DateTime.UtcNow;
            var result = new RealTimeVerdictResult
            {
                Verdict = RealTimeVerdict.Clean,
                RecommendedPolicy = RealTimePolicyAction.Allow,
                RiskScore = 0,
                RiskLevel = RiskLevel.Clean,
                ScanStartTime = scanStart
            };

            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                result.Verdict = RealTimeVerdict.Unknown;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
                result.ThreatDescription = "The file is unavailable; inspection has not completed.";
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
                return result;
            }

            // Öz-koruma bypass: Yalnızca AV'nin kendi bilinen dosyaları atlanır
            if (FileScannerService.IsSelfOwnedPath(filePath))
            {
                // Ek doğrulama: Dosya boyutu makul aralıkta mı? (AV bileşenleri tipik olarak <50MB)
                try
                {
                    var selfFileInfo = new FileInfo(filePath);
                    if (selfFileInfo.Length <= 50 * 1024 * 1024) // 50 MB altı → güvenli bypass
                    {
                        result.ScanEndTime = DateTime.UtcNow;
                        result.VerdictTime = DateTime.UtcNow;
                        return result;
                    }
                    // 50MB üzeri "kendi dosyamız" şüpheli — taramaya devam et
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "Could not inspect self-owned file metadata for {Path}", filePath);
                }
            }

            try
            {
                using var scanLock = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length == 0)
                {
                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // STAGE 0: Fast Shared Scan-Cache Lookup (FileHashMatcher)
                string? verifiedHash = null;
                if (_fileHashMatcher != null)
                {
                    var cached = await _fileHashMatcher.TryGetCachedAsync(filePath, fileInfo, ct);
                    verifiedHash = cached.VerifiedHash;
                    if (cached.Hit && cached.Finding == null && _detectionHub == null)
                    {
                        result.Verdict = RealTimeVerdict.Clean;
                        result.RecommendedPolicy = RealTimePolicyAction.Allow;
                        result.RiskScore = 0;
                        result.RiskLevel = RiskLevel.Clean;
                        result.ThreatTitle = "Doğrulanmış Temiz Dosya (Önbellek)";
                        result.SHA256 = verifiedHash ?? string.Empty;
                        result.ScanEndTime = DateTime.UtcNow;
                        result.VerdictTime = DateTime.UtcNow;
                        return result;
                    }
                }

                var ext = fileInfo.Extension.ToLowerInvariant();

                // STAGE 1: Fast Hash & Signature Database Check
                var sha256 = verifiedHash ?? await _hashService.ComputeSha256Async(filePath, ct);
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(sha256)) throw new IOException("File hashing failed; no clean verdict is available.");
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


                // Check Known Malware Signatures (EICAR, Ransomware, Droppers, Keyloggers)
                var hashMatch = !string.IsNullOrEmpty(sha256) ? MalwareSignatureDatabase.CheckHash(sha256) : new MalwareSignatureMatch();
                if (!hashMatch.IsMatched)
                {
                    var downloadedMatch = ThreatSignatureDatabase.CheckHash(sha256);
                    if (downloadedMatch.IsMatched)
                        hashMatch = new MalwareSignatureMatch
                        {
                            IsMatched = true, ThreatName = downloadedMatch.Name,
                            ThreatCategory = downloadedMatch.Category, SeverityScore = downloadedMatch.Severity,
                            DetectionMethod = "Verified local threat feed hash"
                        };
                }
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

                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // Hash-bound and explicit path exclusions apply only after the exact local signature check.
                if (_exclusionService?.IsExcluded(filePath, sha256) == true)
                {
                    result.ThreatDescription = "Explicit user exclusion; deep inspection was not performed.";
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

                            result.ScanEndTime = DateTime.UtcNow;
                            result.VerdictTime = DateTime.UtcNow;
                            return result;
                        }
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception ex)
                    {
                        _logger?.LogDebug(ex, "Optional cloud reputation lookup failed for {Path}; continuing local inspection", filePath);
                    }
                }

                if (_detectionHub != null)
                {
                    await InspectWithDetectionHubAsync(result, fileInfo, sha256, ct);
                    return result;
                }

                // Check Pattern & YARA-like Rules & API Indicators (EICAR, Keyloggers, Mimikatz, ShadowCopy Deletion)
                var (patternMatch, apiMatches) = await MalwareSignatureDatabase.CheckFileContentAndApisAsync(filePath, ct);
                bool isExactContentSignature = patternMatch.IsMatched &&
                    (patternMatch.DetectionMethod.Equals("Statik İçerik İmzası", StringComparison.OrdinalIgnoreCase) ||
                     patternMatch.ThreatCategory.Equals("TestMalware", StringComparison.OrdinalIgnoreCase));
                if (isExactContentSignature)
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

                    result.ScanEndTime = DateTime.UtcNow;
                    result.VerdictTime = DateTime.UtcNow;
                    return result;
                }

                // STAGE 2: Digital Signature & Trusted Software Policy (Fast-Path Bypass)
                var sigInfo = await _signatureVerifier.VerifySignatureAsync(filePath, ct);
                // Signature is supporting evidence only; continue to content analysis.

                // STAGE 3: Entropy & PE Heuristics
                var entropy = await EntropyCalculator.CalculateEntropyAsync(filePath, ct);
                bool isExe = DangerousExtensions.Contains(ext);
                var peAnalysis = isExe || HasExecutableMagicBytes(scanLock) ? PeAnalyzer.Analyze(filePath) : new PeAnalysisResult();

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

                // Genel PowerShell/ransomware/mimikatz metin desenleri kesin imza değil,
                // destekleyici sezgisel kanıttır. Kaynak kodu ve yönetim scriptlerini tek bir
                // substring yüzünden otomatik karantinaya almamak için skora sınırlı eklenir.
                if (patternMatch.IsMatched && !isExactContentSignature)
                {
                    score = Math.Clamp(score + Math.Min(45, patternMatch.SeverityScore), 0, 100);
                    reasons.Insert(0, $"+{Math.Min(45, patternMatch.SeverityScore)} Sezgisel içerik deseni: {patternMatch.ThreatName}");
                }

                // Çoklu Sinyal Korelasyonu: RiskScoringEngine tarafından hesaplanan seviyeyi ve skoru güncelle
                riskLevel = score switch
                {
                    >= 85 when riskLevel == RiskLevel.ConfirmedMalicious => RiskLevel.ConfirmedMalicious,
                    >= 70 => RiskLevel.HighRisk,
                    >= 50 => RiskLevel.Suspicious,
                    _ => RiskLevel.Clean
                };

                result.RiskScore = score;
                result.RiskLevel = riskLevel;
                result.Evidences.AddRange(reasons);

                // Kontrol Noktası (c) - Tespit Sonrası Aksiyon Öncesi:
                // Herhangi bir dedektör veya sezgisel tespit üretmiş olsa dahi,
                // dosya yolu veya hash istisna listesinde ise engelleme yapılmaz, Clean/Allow döner.
                if (_exclusionService != null && _exclusionService.IsExcluded(filePath, sha256))
                {
                    result.Verdict = RealTimeVerdict.Clean;
                    result.RecommendedPolicy = RealTimePolicyAction.Allow;
                    result.RiskScore = 0;
                    result.RiskLevel = RiskLevel.Clean;
                    result.ThreatTitle = string.Empty;
                    result.ThreatDescription = "Kullanıcı istisna listesinde (Exclusion) yer alıyor.";
                    result.Evidences.Clear();
                    fileInfo.Refresh();
                    _fileHashMatcher?.SetCache(filePath, fileInfo.Length, fileInfo.LastWriteTimeUtc, null, sha256, false, false);
                    return result;
                }

                // Confirmed actions were already returned by exact hash/content signatures.
                // A heuristic sum, even 100, is not proof of maliciousness.
                if (riskLevel >= RiskLevel.HighRisk || score >= 70)
                {
                    result.RiskLevel = RiskLevel.HighRisk;
                    result.Verdict = RealTimeVerdict.Suspicious;
                    result.RecommendedPolicy = RealTimePolicyAction.Warn;
                    result.Confidence = 0.75;
                    result.ThreatTitle = $"⚠️ Yüksek Riskli Dosya Uyarısı: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                // RiskScore 50-69: Uyarı (İzin ver + Logla + Kullanıcı Uyarısı, SİLME)
                else if (score >= 50)
                {
                    result.Verdict = RealTimeVerdict.Suspicious;
                    result.RecommendedPolicy = RealTimePolicyAction.Warn;
                    result.Confidence = 0.55;
                    result.ThreatTitle = $"⚠️ Şüpheli Dosya Uyarısı: {fileInfo.Name}";
                    result.ThreatDescription = string.Join(" ", reasons.Take(2));
                }
                else
                {
                    result.Verdict = RealTimeVerdict.Clean;
                    result.RecommendedPolicy = RealTimePolicyAction.Allow;
                    result.Confidence = 0.90;
                    fileInfo.Refresh();
                    _fileHashMatcher?.SetCache(filePath, fileInfo.Length, fileInfo.LastWriteTimeUtc, null, sha256, false, false);
                }

            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                result.Verdict = RealTimeVerdict.Unknown;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
                result.ThreatTitle = "Inspection unavailable";
                result.Evidences.Add(ex.GetType().Name);
                _logger?.LogTrace(ex, "Inspection failed for {Path}", filePath);
            }
            finally
            {
                result.ScanEndTime = DateTime.UtcNow;
                result.VerdictTime = DateTime.UtcNow;
            }

            return result;
        }

        private async Task InspectWithDetectionHubAsync(RealTimeVerdictResult result, FileInfo file, string sha256, CancellationToken ct)
        {
            var shared = new ScanContext(file.FullName, sha256, file.Length) { LastWriteTimeUtc = file.LastWriteTimeUtc };
            var detection = await _detectionHub!.EvaluateAsync(shared.ToDetectionContext(), ct);
            ct.ThrowIfCancellationRequested();
            result.RiskScore = detection.RiskScore;
            result.Confidence = detection.OverallConfidence == EvidenceConfidence.Absolute ? 0.99 :
                detection.OverallConfidence == EvidenceConfidence.High ? 0.8 : 0.5;
            result.ThreatTitle = detection.ThreatTitle;
            result.Evidences.AddRange(detection.Evidences.Select(e => $"[{e.Category}] {e.Description}"));
            result.ThreatDescription = string.Join(" | ", detection.Evidences.Take(2).Select(e => e.Description));
            bool exact = detection.Verdict == DetectionVerdict.ConfirmedMalicious && detection.Evidences.Any(e =>
                e.Category == EvidenceCategory.StaticSignature && e.Confidence == EvidenceConfidence.Absolute && e.ScoreContribution >= 80);
            if (exact)
            {
                result.Verdict = RealTimeVerdict.ConfirmedMalicious;
                result.RiskLevel = RiskLevel.ConfirmedMalicious;
                result.RecommendedPolicy = RealTimePolicyAction.BlockAndQuarantine;
            }
            else if (!detection.IsComplete || detection.FailedDetectorCount > 0 || detection.Verdict == DetectionVerdict.Unknown)
            {
                result.Verdict = RealTimeVerdict.Unknown;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
                result.ThreatDescription = "Inspection incomplete: " + string.Join("; ", detection.CoverageLimitations);
                result.Evidences.Add($"Failed detectors: {detection.FailedDetectorCount}");
            }
            else if (detection.RiskScore >= 50)
            {
                result.Verdict = RealTimeVerdict.Suspicious;
                result.RiskLevel = detection.RiskScore >= 70 ? RiskLevel.HighRisk : RiskLevel.Suspicious;
                result.RecommendedPolicy = RealTimePolicyAction.Warn;
            }
            else if (detection.Verdict != DetectionVerdict.Clean)
            {
                result.Verdict = RealTimeVerdict.Suspicious;
                result.RiskLevel = RiskLevel.LowRisk;
                result.RecommendedPolicy = RealTimePolicyAction.Observe;
            }
            else
            {
                result.Verdict = RealTimeVerdict.Clean;
                result.RiskLevel = RiskLevel.Clean;
                result.RecommendedPolicy = RealTimePolicyAction.Allow;
                _fileHashMatcher?.SetCache(file.FullName, file.Length, file.LastWriteTimeUtc, null, sha256, false, false);
            }
        }

        /// <summary>
        /// Dosyanın ilk baytlarını kontrol ederek çalıştırılabilir bir dosya olup olmadığını tespit eder.
        /// MZ (PE), PK (ZIP/JAR), ELF magic byte'ları kontrol edilir.
        /// </summary>
        private static bool HasExecutableMagicBytes(FileStream fs)
        {
                fs.Position = 0;
                Span<byte> header = stackalloc byte[4];
                int read = fs.Read(header);
                if (read < 2) return false;

                // MZ → PE executable
                if (header[0] == 0x4D && header[1] == 0x5A) return true;
                // PK → ZIP archive (potential JAR, DOCM, etc.)
                if (header[0] == 0x50 && header[1] == 0x4B) return true;
                // ELF → Linux executable (unlikely on Windows but defensive)
                if (read >= 4 && header[0] == 0x7F && header[1] == 0x45 && header[2] == 0x4C && header[3] == 0x46) return true;

                return false;
        }
    }
}
