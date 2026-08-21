using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Services;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;

namespace AegisPC.Security.RealTime
{
    public enum WatchdogActionVerdict
    {
        LegitimateGameFile = 0,
        SuspiciousCrossFolderDrop = 1,
        CredentialStealingAttempt = 2,
        PersistenceTamper = 3
    }

    public class WatchdogEvaluationResult
    {
        public bool IsMalicious { get; set; }
        public WatchdogActionVerdict Verdict { get; set; }
        public string ThreatTitle { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int RiskScore { get; set; }
    }

    public class GameCrackWatchdogShield
    {
        private static readonly HashSet<string> SafeGameExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".sav", ".save", ".dat", ".ini", ".cfg", ".json", ".xml", ".log",
            ".txt", ".replay", ".pak", ".bin", ".dds", ".png", ".tga", ".mp3"
        };

        private static readonly HashSet<string> DangerousDropExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".scr", ".hta", ".cpl"
        };

        public bool IsGameOrSandboxProcess(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath)) return false;

            if (GameCrackClassifier.IsGameCrackOrEmulator(executablePath)) return true;

            var lower = executablePath.ToLowerInvariant();
            return lower.Contains(@"\games\") ||
                   lower.Contains(@"\oyunlar\") ||
                   lower.Contains("-steam") ||
                   lower.Contains(@"\steamapps\") ||
                   lower.Contains(@"\bin64\") ||
                   lower.Contains("beamng") ||
                   lower.Contains("gta5") ||
                   lower.Contains("cyberpunk");
        }

        public WatchdogEvaluationResult EvaluateActivity(
            string processExePath,
            string targetPath)
        {
            if (string.IsNullOrWhiteSpace(targetPath))
            {
                return new WatchdogEvaluationResult { IsMalicious = false, Verdict = WatchdogActionVerdict.LegitimateGameFile };
            }

            var targetLower = targetPath.ToLowerInvariant();
            var ext = Path.GetExtension(targetPath).ToLowerInvariant();

            // 1. Credential & Sensitive Token Stealing Testi (XOR maskeli)
            if (targetLower.Contains(AegisPC.Security.Common.SecObfuscator.Unmask(new byte[] { 6, 54, 53, 61, 51, 52, 122, 62, 59, 46, 59 })) ||
                targetLower.Contains(AegisPC.Security.Common.SecObfuscator.Unmask(new byte[] { 6, 45, 63, 56, 122, 62, 59, 46, 59 })) ||
                targetLower.Contains(AegisPC.Security.Common.SecObfuscator.Unmask(new byte[] { 6, 57, 53, 53, 49, 51, 63, 41 })) ||
                targetLower.Contains(AegisPC.Security.Common.SecObfuscator.Unmask(new byte[] { 62, 51, 41, 57, 53, 40, 62, 6, 54, 53, 57, 59, 54, 122, 41, 46, 53, 40, 59, 61, 63 })) ||
                targetLower.Contains(AegisPC.Security.Common.SecObfuscator.Unmask(new byte[] { 6, 46, 63, 54, 63, 61, 40, 59, 55, 122, 62, 63, 41, 49, 46, 53, 42, 6, 46, 62, 59, 46, 59 })))
            {
                return new WatchdogEvaluationResult
                {
                    IsMalicious = true,
                    Verdict = WatchdogActionVerdict.CredentialStealingAttempt,
                    ThreatTitle = "🚨 Korsan/Oyun Süreci Tarayıcı Şifrelerini Çalmaya Çalışıyor!",
                    Description = $"Oyun süreci ({Path.GetFileName(processExePath)}) korumalı tarayıcı veritabanına ({targetPath}) yetkisiz erişim girişiminde bulundu.",
                    RiskScore = 95
                };
            }

            // 2. Persistence & Startup Enjeksiyonu
            if (targetLower.Contains(@"\startup\") || 
                targetLower.Contains(@"\start menu\programs\startup\"))
            {
                return new WatchdogEvaluationResult
                {
                    IsMalicious = true,
                    Verdict = WatchdogActionVerdict.PersistenceTamper,
                    ThreatTitle = "🚨 Başlangıca Gizli Kalıcılık Enjeksiyonu",
                    Description = $"Oyun süreci Windows başlangıcına yetkisiz dosya eklemeye çalışıyor: {targetPath}",
                    RiskScore = 90
                };
            }

            // 3. Çapraz Dizin Binary / Script Dropper (Temp/Windows/System32)
            if (DangerousDropExtensions.Contains(ext))
            {
                bool isInsideOwnDir = !string.IsNullOrWhiteSpace(processExePath) &&
                                      targetLower.StartsWith(Path.GetDirectoryName(processExePath)!.ToLowerInvariant());

                if (!isInsideOwnDir)
                {
                    if (targetLower.Contains(@"\temp\") || 
                        targetLower.Contains(@"\windows\") ||
                        targetLower.Contains(@"\appdata\roaming\microsoft\"))
                    {
                        return new WatchdogEvaluationResult
                        {
                            IsMalicious = true,
                            Verdict = WatchdogActionVerdict.SuspiciousCrossFolderDrop,
                            ThreatTitle = "🚨 Çapraz Dizin Zararlı Yayılımı (Dropper)",
                            Description = $"Oyun süreci ({Path.GetFileName(processExePath)}) kendi dizini dışındaki geçici konuma çalıştırılabilir kod attı: {targetPath}",
                            RiskScore = 85
                        };
                    }
                }
            }

            // 4. Meşru oyun kayıtları (Documents, AppData, Saved Games'te save/config yazma)
            return new WatchdogEvaluationResult
            {
                IsMalicious = false,
                Verdict = WatchdogActionVerdict.LegitimateGameFile,
                Description = "Meşru oyun kayıt ve yapılandırma dosyası (SaveGame/Config).",
                RiskScore = 0
            };
        }
    }
}