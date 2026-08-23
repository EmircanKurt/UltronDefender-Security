using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning
{
    public class RiskScoringEngine : IRiskScoringEngine
    {
        private static readonly HashSet<string> ExactPupKeywords = new(StringComparer.OrdinalIgnoreCase)
        {
            "crack", "keygen", "activator", "repack", "hacktool", "trainer", 
            "cheat", "kmsauto", "kmspico", "hwidgen", "injector", "spoofer"
        };

        public async Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(
            FileAnalysisResult result,
            CancellationToken cancellationToken = default)
        {
            int score = 0;
            var reasons = new List<string>();

            bool isGameOrRepack = PathHelper.IsGameOrRepackDirectory(result.FilePath) || GameCrackClassifier.IsGameCrackOrEmulator(result.FilePath);

            // 1. Digital Signature & Known Location Safe Modifiers
            if (result.IsSigned && result.SignatureValid)
            {
                // Verified trusted digital signature reduces risk significantly
                score -= 40;
                reasons.Add($"-40 Doğrulanmış dijital imza: '{result.SignaturePublisher ?? "Güvenilir Yayımcı"}'");
            }

            if (result.IsKnownLocation)
            {
                // System32 or Program Files location
                score -= 30;
                reasons.Add("-30 Güvenilir Windows sistem konumu (System32 / Program Files)");
            }

            if (isGameOrRepack)
            {
                // Oyun/Repack/Emülatör/Trainer İstisnası: Meşru oyun hileleri ve emülatörler için temel güven indirimi
                score -= 25;
                reasons.Add("-25 Oyun/Repack/Emülatör Güvenlik Muafiyeti (Gamer Protection Shield)");
            }

            // 2. PUP / Crack / Keygen Pattern Heuristics (ONLY for unsigned files outside known safe/game locations)
            if (!result.IsSigned && !result.IsKnownLocation && !isGameOrRepack)
            {
                var fileNameOnly = Path.GetFileNameWithoutExtension(result.FileName).ToLowerInvariant();
                var tokens = fileNameOnly.Split(new[] { '.', '-', '_', ' ' }, StringSplitOptions.RemoveEmptyEntries);

                bool isPupPattern = tokens.Any(t => ExactPupKeywords.Contains(t)) ||
                                    ExactPupKeywords.Any(k => fileNameOnly.Equals(k, StringComparison.OrdinalIgnoreCase));

                if (isPupPattern)
                {
                    score += 50;
                    reasons.Add("+50 Potansiyel İstenmeyen / Korsan Yazılım (PUP/Crack/Keygen) deseni");
                }
            }

            // 3. High-Risk Location Checks (Temp, Hidden Drop Zones)
            var path = result.FilePath;
            bool isInstalledAppFolder = path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase) ||
                                       path.Contains(@"\AppData\Local\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase);

            if (PathHelper.IsTempPath(path) || path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
            {
                score += 25;
                reasons.Add("+25 Dosya geçici dizinde (Temp) çalıştırılıyor / indirildi");
            }
            else if (path.Contains(@"\AppData\Roaming\", StringComparison.OrdinalIgnoreCase) && !result.IsSigned && !isInstalledAppFolder && !isGameOrRepack)
            {
                score += 10;
                reasons.Add("+10 İmzasız dosya kullanıcı AppData\\Roaming dizininde");
            }
            else if (PathHelper.IsUserDownloadsPath(path) && !result.IsSigned && !isGameOrRepack)
            {
                score += 10;
                reasons.Add("+10 İmzasız dosya İndirilenler (Downloads) klasöründe");
            }

            // 4. Shannon Entropy & Packer Heuristics (Calibrated for Cracks/Packers)
            // NOT: Yüksek entropi ve bilinen packer'lar (UPX, Themida, VMProtect) tek başına dosyayı ConfirmedMalicious yapmaz.
            if (!isGameOrRepack)
            {
                if (result.IsPacked)
                {
                    string pName = result.PackerName ?? "UPX/Themida/VMProtect";
                    score += 20;
                    reasons.Add($"+20 Paketlenmiş/Korunmuş Yürütülebilir ({pName}) — Bu durum crack ve korumalı yazılımlar için olağandır.");
                }
                else if (result.Entropy >= 7.85)
                {
                    score += 25;
                    reasons.Add($"+25 Aşırı yüksek Shannon entropisi ({result.Entropy:F2} / 8.0) — Şifrelenmiş/Paketlenmiş veri");
                }
                else if (result.Entropy >= 7.5 && !result.IsSigned && !result.IsKnownLocation && !isInstalledAppFolder)
                {
                    score += 15;
                    reasons.Add($"+15 Yüksek Shannon entropisi ({result.Entropy:F2} / 8.0)");
                }
            }

            // 5. File extension disguise check (e.g. .pdf.exe or .docx.scr)
            if (result.FileName.Count(c => c == '.') > 1)
            {
                var lower = result.FileName.ToLowerInvariant();
                if ((lower.EndsWith(".exe") || lower.EndsWith(".scr") || lower.EndsWith(".vbs") || lower.EndsWith(".bat") || lower.EndsWith(".cmd") || lower.EndsWith(".ps1")) &&
                    (lower.Contains(".pdf.") || lower.Contains(".docx.") || lower.Contains(".xlsx.") || lower.Contains(".jpg.") || lower.Contains(".png.")))
                {
                    score += 75;
                    reasons.Add("+75 Çift uzantı kamuflajı tespit edildi (Örn: .pdf.exe aldatmacası)");
                }
            }

            // 6. Unsigned Executable Penalty (Only outside of known system/installed app/game directories)
            if (!result.IsSigned && result.IsExecutable && !result.IsKnownLocation && !isInstalledAppFolder && !isGameOrRepack)
            {
                score += 10;
                reasons.Add("+10 Yürütülebilir dosya dijital olarak imzalanmamış");
            }

            // 7. Multi-Signal Suspicious Win32 API & Behavioral Indicators (Only for unsigned binaries in untrusted paths)
            bool isKnownSafe = result.IsKnownLocation || PathHelper.IsKnownSafePath(result.FilePath);
            if (!result.IsSigned && !isKnownSafe && !string.IsNullOrEmpty(result.FilePath) && File.Exists(result.FilePath))
            {
                var apis = await MalwareSignatureDatabase.ScanApiIndicatorsAsync(result.FilePath, cancellationToken);
                foreach (var api in apis)
                {
                    // Oyun ve crack dosyalarında bellek hook'lama (VirtualAllocEx, SetWindowsHookEx) doğal olduğundan ağırlık hafifletilir
                    int effectiveWeight = isGameOrRepack ? Math.Max(2, api.Weight / 4) : api.Weight;
                    score += effectiveWeight;
                    reasons.Add($"+{effectiveWeight} API Göstergesi: {api.Description}" + (isGameOrRepack ? " (Oyun Modu İndirimi)" : ""));
                }
            }

            // Microsoft or trusted OS binaries: zero risk ONLY IF in legitimate system/program directories.
            // If placed in Temp/Downloads/untrusted drop zones, reduce risk but do not zero it (prevents LOLBin staging).
            if (result.IsSigned && result.SignatureValid && result.SignaturePublisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true)
            {
                if (result.IsKnownLocation || PathHelper.IsKnownSafePath(result.FilePath))
                {
                    score = 0;
                }
                else
                {
                    score = Math.Max(0, score - 30);
                }
            }
            else if (PathHelper.IsSystemPath(result.FilePath) && result.IsKnownLocation)
            {
                score = 0;
            }

            // Clamp score between 0 and 100
            score = Math.Clamp(score, 0, 100);

            // Calibrated Levels:
            // 0-49: Clean
            // 50-69: Suspicious (Medium)
            // 70-84: HighRisk (PUP/Crack or High Risk)
            // 85-100: ConfirmedMalicious (Critical)
            RiskLevel level = score switch
            {
                >= 85 => RiskLevel.ConfirmedMalicious,
                >= 70 => RiskLevel.HighRisk,
                >= 50 => RiskLevel.Suspicious,
                _ => RiskLevel.Clean
            };

            return (score, level, reasons);
        }
    }
}
