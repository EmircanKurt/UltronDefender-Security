using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using System.Collections.Concurrent;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning
{
    public class RiskScoringEngine : IRiskScoringEngine
    {
        // Bilinen İstenmeyen Program (PUP) ve Hacktool SHA-256 Hash Veritabanı
        private static readonly HashSet<string> KnownPupHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            "E186411FB272847B3E39FCE160B5B110B6343585F84AE8BE98E9B9735F646C0B", // KMSAuto Net
            "02D39620BB9396349F579051833501A74808C78A4BA14C5D76C68564F7986B74", // KMSPico
            "FA01C312DA95D1E168341517454944BA7F27CE2B68DC99F26E650DA90E8F0EF1", // HWIDGen
            "99B2319A56E215BAE99F98822B7853A90DE670498F4F5234D3C579E7802D310C", // Universal Keygen
            "44537E9E8ADEC52DF2CD7CE1111666870FE97FF83A3B95C3DF5D2590BA5EC97B", // XMRig Coinminer
            "CC8B4F923D19FE28BB67417B69201C7FA1D54F923D19FE28BB67417B69201C7F", // Mimikatz x64
            "8D4E2F6C7D382A2A9A8D65F066B925D8F6AE2D48EC3C51A848CD169A1DF16538", // LaZagne Dumper
            "B84C42A27A7950E4631D61D2B52D4F780FBE6C687E907B65E4790EE82E113942", // ProcessHacker Dropper
            "D2D68C090C8FF2DF94738BBE9048E6E77D3220455B2AE5743452932CF7DC49E2", // Adware.Generic Bundler
            "A5E9C8861B85D94D581F7D74B4699042539A8F53B78F0945EB0E663B5F6C6D68"  // WebBrowserPassView PUP
        };

        // Çalışma zamanında veya güncellemeyle eklenebilir dinamik PUP/Hacktool hash kümesi
        private static readonly ConcurrentDictionary<string, byte> DynamicPupHashes = new(StringComparer.OrdinalIgnoreCase);
        private const int MaxDynamicPupHashes = 100000;

        public static void RegisterPupHash(string sha256)
        {
            if (!string.IsNullOrWhiteSpace(sha256))
            {
                if (DynamicPupHashes.Count < MaxDynamicPupHashes)
                {
                    DynamicPupHashes.TryAdd(sha256.Trim(), 0);
                }
            }
        }

        public static bool IsKnownPupHash(string? sha256)
        {
            if (string.IsNullOrWhiteSpace(sha256)) return false;
            return KnownPupHashes.Contains(sha256) || DynamicPupHashes.ContainsKey(sha256);
        }

        // TR: Bu metod; dosyanın dijital imza, konum, PE entropi, şüpheli API göstergeleri ve bilinen
        //     zararlı veritabanı eşleşmelerine göre 0-100 arası ağırlıklı risk skorunu ve kategorisini hesaplar.
        // EN: This method calculates the weighted risk score (0-100) and classification for a file based on
        //     digital signatures, location heuristics, PE entropy, suspicious API indicators, and known threat databases.
        public async Task<(int score, RiskLevel level, List<string> reasons)> CalculateRiskScoreAsync(
            FileAnalysisResult result,
            CancellationToken cancellationToken = default)
        {
            int score = 0;
            var reasons = new List<string>();

            bool isVerifiedGameBinary = GameCrackClassifier.IsGameCrackOrEmulator(result.FilePath);

            bool isKnownPup = IsKnownPupHash(result.SHA256);

            // TR: Aşama 0: Merkezi Güven Politikası (TrustedSoftwarePolicy) değerlendirmesi
            var trust = AegisPC.Security.Safety.TrustedSoftwarePolicy.EvaluateTrust(
                result.FilePath,
                result.SignaturePublisher,
                result.IsSigned,
                result.SignatureValid,
                result.IsKnownLocation);

            if (trust.IsFullyTrusted && !isKnownPup)
            {
                reasons.Add($"-100 {trust.Reason}");
                return (0, RiskLevel.Clean, reasons);
            }

            // TR: Aşama 1: Dijital imza geçerliliği ve güvenilir sistem dizini (System32/Program Files) kontrolleri.
            // EN: Stage 1: Verified digital signature and trusted system directories (System32/Program Files).
            // 1. Digital Signature & Known Location Safe Modifiers
            if (result.IsSigned && result.SignatureValid)
            {
                int discount = trust.TrustScoreDiscount < 0 ? trust.TrustScoreDiscount : -40;
                score += discount;
                reasons.Add($"{discount} {trust.Reason}");
            }

            if (result.IsKnownLocation)
            {
                // System32 or Program Files location
                score -= 30;
                reasons.Add("-30 Güvenilir Windows sistem konumu (System32 / Program Files)");
            }

            if (isVerifiedGameBinary && !isKnownPup)
            {
                // Verified PE export proxy or known emulator hash documentation note (No arbitrary score discount to prevent bypass)
                reasons.Add("Oyun/Emülatör PE Yapı Doğrulaması (Gamer Protection)");
            }

            // TR: Aşama 2: Kural 7.1 uyumlu PUP/Hacktool tespiti; bilinen hash eşleşmesi veya açık hacktool/packer anomalisi
            // EN: Stage 2: Rule 7.1-calibrated PUP/Hacktool detection via known hashes or verified hacktool/packer anomalies
            // 2. PUP / Hacktool Detection via Digital Trust, PE Behavior & Known Hashes
            if (isKnownPup)
            {
                score += 50;
                reasons.Add("+50 Bilinen İstenmeyen Program / Hacktool imzası (Hash Veritabanı Eşleşmesi)");
            }
            else if (!result.IsSigned && !result.IsKnownLocation)
            {
                bool isPup = false;
                string pupReason = string.Empty;

                if (!isPup && result.IsExecutable && !isVerifiedGameBinary)
                {
                    bool isUserWorkArea = PathHelper.IsUserDownloadsPath(result.FilePath) ||
                                          result.FilePath.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) ||
                                          result.FilePath.Contains(@"\Documents\", StringComparison.OrdinalIgnoreCase) ||
                                          result.FilePath.Contains(@"\Belgeler\", StringComparison.OrdinalIgnoreCase) ||
                                          result.FilePath.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase) ||
                                          result.FilePath.Contains(@"\Masaüstü\", StringComparison.OrdinalIgnoreCase);

                    bool hasHacktoolIndicator = !string.IsNullOrEmpty(result.FileName) && (
                        result.FileName.Contains("keygen", StringComparison.OrdinalIgnoreCase) ||
                        result.FileName.Contains("crack", StringComparison.OrdinalIgnoreCase) ||
                        result.FileName.Contains("kmsauto", StringComparison.OrdinalIgnoreCase) ||
                        result.FileName.Contains("miner", StringComparison.OrdinalIgnoreCase) ||
                        result.FileName.Contains("patcher", StringComparison.OrdinalIgnoreCase));

                    // İmzasız, kullanıcı alanında; bilinen hacktool adı veya şüpheli packer + yüksek entropi anomalisi
                    bool hasHighEntropyAnomaly = result.Entropy >= 7.6 || (result.IsPacked && result.Entropy >= 7.0);

                    if (isUserWorkArea && (hasHacktoolIndicator || (hasHighEntropyAnomaly && result.IsPacked)))
                    {
                        isPup = true;
                        pupReason = "+50 Potansiyel İstenmeyen / Korsan Yazılım (PUP/Crack/Keygen) davranış kalıbı (İmzasız, Kullanıcı Alanı ve Şüpheli Hacktool / Packer Anomalisi)";
                    }
                }

                if (isPup)
                {
                    score += 50;
                    reasons.Add(pupReason);
                }
            }

            // TR: Aşama 3: Yüksek riskli geçici çalışma alanları (Temp dizinleri ve izole AppData klasörleri) kontrolü.
            // EN: Stage 3: High-risk staging location checks (Temp folders and isolated AppData drop paths).
            // 3. High-Risk Location Checks (Temp, Hidden Drop Zones)
            var path = result.FilePath;
            bool isInstalledAppFolder = path.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase) ||
                                       path.Contains(@"\AppData\Local\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase);

            if (PathHelper.IsTempPath(path) || path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
            {
                score += 25;
                reasons.Add("+25 Dosya geçici dizinde (Temp) çalıştırılıyor / indirildi");
            }
            else if (path.Contains(@"\AppData\Roaming\", StringComparison.OrdinalIgnoreCase) && !result.IsSigned && !isInstalledAppFolder && !isVerifiedGameBinary)
            {
                score += 10;
                reasons.Add("+10 İmzasız dosya kullanıcı AppData\\Roaming dizininde");
            }
            else if ((PathHelper.IsUserDownloadsPath(path) || path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)) && !result.IsSigned && !isVerifiedGameBinary)
            {
                score += 10;
                reasons.Add("+10 İmzasız dosya İndirilenler (Downloads) klasöründe");
            }

            // TR: Aşama 4: Shannon entropi ve paketleyici (packer) analizi; şifreli veya sıkıştırılmış PE bölümlerini tespit eder.
            // EN: Stage 4: Shannon entropy and packer heuristics; detects encrypted or compressed PE payload sections.
            // 4. Shannon Entropy & Packer Heuristics (Calibrated for Cracks/Packers as corroborating evidence)
            if (!isVerifiedGameBinary)
            {
                if (result.IsPacked)
                {
                    string pName = result.PackerName ?? "UPX/Themida/VMProtect";
                    // Destekleyici kanıt kuralı: Bilinen packer tek başına dosya bloklamasın. Yalnızca tehdit/hacktool göstergesiyle birleştiğinde +20 eklenir.
                    bool hasPriorThreatEvidence = isKnownPup || reasons.Any(r => r.Contains("Hacktool", StringComparison.OrdinalIgnoreCase) || r.Contains("PUP", StringComparison.OrdinalIgnoreCase) || r.Contains("kamuflaj", StringComparison.OrdinalIgnoreCase) || r.Contains("API", StringComparison.OrdinalIgnoreCase));
                    if (hasPriorThreatEvidence)
                    {
                        score += 20;
                        reasons.Add($"+20 Paketlenmiş/Korunmuş Yürütülebilir ({pName}) — Tehdit kalıbı ile birleşik korumalı yük");
                    }
                    else
                    {
                        reasons.Add($"Bilinen Paketleyici ({pName}) — Yalnızca sıkıştırma, bağımsız tehdit göstergesi saptanmadı");
                    }
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

            // TR: Aşama 5: Çift uzantı kamuflaj kontrolü (örn. .pdf.exe veya .docx.scr gibi kullanıcıyı aldatmaya yönelik uzantılar).
            // EN: Stage 5: Double extension disguise detection (e.g., .pdf.exe or .docx.scr disguise patterns).
            // 5. File extension disguise check (e.g. .pdf.exe or .docx.scr)
            if (result.FileName.Count(c => c == '.') > 1)
            {
                var lower = result.FileName.ToLowerInvariant();
                if ((lower.EndsWith(".exe") || lower.EndsWith(".scr") || lower.EndsWith(".vbs") || lower.EndsWith(".bat") || lower.EndsWith(".cmd") || lower.EndsWith(".ps1")) &&
                    (lower.Contains(".pdf.") || lower.Contains(".docx.") || lower.Contains(".xlsx.") || lower.Contains(".jpg.") || lower.Contains(".png.")))
                {
                    score += 85;
                    reasons.Add("+85 Çift uzantı kamuflajı tespit edildi (Örn: .pdf.exe aldatmacası)");
                }
            }

            // TR: Aşama 6: İmzasız çalıştırılabilir dosya risk cezası (yalnızca güvenilir olmayan yollardaki ikililer için).
            // EN: Stage 6: Unsigned executable risk penalty (only applied to binaries outside trusted system/app folders).
            // 6. Unsigned Executable Penalty (Only outside of known system/installed app/game directories)
            if (!result.IsSigned && result.IsExecutable && !result.IsKnownLocation && !isInstalledAppFolder && !isVerifiedGameBinary)
            {
                score += 10;
                reasons.Add("+10 Yürütülebilir dosya dijital olarak imzalanmamış");
            }

            // TR: Aşama 7: Çoklu sinyalli şüpheli Win32 API ve davranışsal gösterge analizi (Bellek Enjeksiyonu, Process Hollowing, Keylogger).
            // EN: Stage 7: Multi-signal suspicious Win32 API and behavioral indicator analysis (Process Injection, Process Hollowing, Keylogger).
            // 7. Multi-Signal Suspicious Win32 API & Behavioral Indicators (Only for unsigned binaries in untrusted paths)
            bool isKnownSafe = result.IsKnownLocation || PathHelper.IsKnownSafePath(result.FilePath);
            if (!result.IsSigned && !isKnownSafe && !string.IsNullOrEmpty(result.FilePath) && File.Exists(result.FilePath))
            {
                var apis = await MalwareSignatureDatabase.ScanApiIndicatorsAsync(result.FilePath, cancellationToken);
                bool hasInjectionOrHollowing = false;
                foreach (var api in apis)
                {
                    // Oyun ve crack dosyalarında bellek hook'lama (VirtualAllocEx, SetWindowsHookEx) doğal olduğundan ağırlık hafifletilir
                    int effectiveWeight = isVerifiedGameBinary ? Math.Max(2, api.Weight / 4) : api.Weight;
                    score += effectiveWeight;
                    reasons.Add($"+{effectiveWeight} API Göstergesi: {api.Description}" + (isVerifiedGameBinary ? " (Oyun Modu İndirimi)" : ""));

                    if (api.ApiName.Contains("VirtualAlloc", StringComparison.OrdinalIgnoreCase) ||
                        api.ApiName.Contains("WriteProcessMemory", StringComparison.OrdinalIgnoreCase) ||
                        api.ApiName.Contains("NtUnmapViewOfSection", StringComparison.OrdinalIgnoreCase) ||
                        api.ApiName.Contains("CreateRemoteThread", StringComparison.OrdinalIgnoreCase) ||
                        api.ApiName.Contains("QueueUserAPC", StringComparison.OrdinalIgnoreCase))
                    {
                        hasInjectionOrHollowing = true;
                    }
                }

                // PE Davranışsal Göstergeler: İmzasız ikilide bellek enjeksiyonu veya process hollowing tespiti
                if (hasInjectionOrHollowing && !isVerifiedGameBinary && !reasons.Any(r => r.Contains("PUP")))
                {
                    score += 20;
                    reasons.Add("+20 PE Davranışsal Gösterge: Bellek enjeksiyonu veya Process Hollowing API tespiti");
                }
            }

            // TR: Aşama 8: Microsoft imzalı güvenilir ikililer için LOLBin koruması ve skorun 0-100 aralığına sınırlandırılması.
            // EN: Stage 8: LOLBin mitigation for Microsoft-signed binaries and score clamping between 0 and 100.
            // Microsoft or trusted OS binaries: zero risk ONLY IF in legitimate system/program directories.
            // If placed in Temp/Downloads/untrusted drop zones, reduce risk but do not zero it (prevents LOLBin staging).
            if (!isKnownPup && result.IsSigned && result.SignatureValid && 
                (result.SignaturePublisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true ||
                 result.SignaturePublisher?.Contains("Windows", StringComparison.OrdinalIgnoreCase) == true))
            {
                if (result.IsKnownLocation || PathHelper.IsKnownSafePath(result.FilePath) || AegisPC.Security.Safety.TrustedSoftwarePolicy.IsLegitimateInstallLocation(result.FilePath))
                {
                    score = 0;
                }
                else
                {
                    score = Math.Max(0, score - 30);
                }
            }
            else if (!isKnownPup && PathHelper.IsSystemPath(result.FilePath) && result.IsKnownLocation)
            {
                score = 0;
            }

            // Clamp score between 0 and 100
            score = Math.Clamp(score, 0, 100);

            // TR: Kalibre edilmiş risk seviyesi bantları (0-49: Temiz, 50-69: Şüpheli, 70-84: Yüksek Risk/PUP, 85-100: Kesin Zararlı).
            // EN: Calibrated risk level thresholds (0-49: Clean, 50-69: Suspicious, 70-84: HighRisk/PUP, 85-100: ConfirmedMalicious).
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
