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
        // Bilinen İstenmeyen Program (PUP) ve Hacktool SHA-256 Hash Veritabanı
        private static readonly HashSet<string> KnownPupHashes = new(StringComparer.OrdinalIgnoreCase)
        {
            "E186411FB272847B3E39FCE160B5B110B6343585F84AE8BE98E9B9735F646C0B", // KMSAuto Net
            "02D39620BB9396349F579051833501A74808C78A4BA14C5D76C68564F7986B74", // KMSPico
            "FA01C312DA95D1E168341517454944BA7F27CE2B68DC99F26E650DA90E8F0EF1", // HWIDGen
            "99B2319A56E215BAE99F98822B7853A90DE670498F4F5234D3C579E7802D310C"  // Universal Keygen
        };

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

            bool isGameOrRepack = PathHelper.IsGameOrRepackDirectory(result.FilePath) || GameCrackClassifier.IsGameCrackOrEmulator(result.FilePath);

            // TR: Aşama 1: Dijital imza geçerliliği, güvenilir sistem dizini (System32/Program Files) ve oyun muafiyeti kontrolleri.
            // EN: Stage 1: Verified digital signature, trusted system directories (System32/Program Files), and gamer protection exemptions.
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

            // TR: Aşama 2: Kural 7.1 uyumlu PUP/Hacktool tespiti; dosya adına bakılmaksızın sadece SHA-256 hash
            //     ve imzasız ikililerde kullanıcı çalışma alanı anomalileriyle belirlenir.
            // EN: Stage 2: Rule 7.1-compliant PUP/Hacktool detection; determined purely via SHA-256 hash lookup
            //     and unsigned binary workspace anomalies without inspecting file names.
            // 2. PUP / Hacktool Detection via Digital Trust, PE Behavior & Known Hashes (Rule 7.1 Compliant - No Magic String)
            if (!result.IsSigned && !result.IsKnownLocation && !isGameOrRepack)
            {
                bool isPup = false;
                string pupReason = string.Empty;

                // Kriter 3: Bilinen Hash Eşleşmesi
                if (!string.IsNullOrEmpty(result.SHA256) && KnownPupHashes.Contains(result.SHA256))
                {
                    isPup = true;
                    pupReason = "+50 Bilinen İstenmeyen Program / Hacktool imzası (Hash Veritabanı Eşleşmesi)";
                }

                // Kriter 1 & 2: Dijital İmza Durumu (İmzasız) + Belirli Davranış Kalıpları
                if (!isPup && result.IsExecutable)
                {
                    bool isUserWorkArea = PathHelper.IsUserDownloadsPath(result.FilePath) ||
                                          result.FilePath.Contains(@"\Documents\", StringComparison.OrdinalIgnoreCase) ||
                                          result.FilePath.Contains(@"\Belgeler\", StringComparison.OrdinalIgnoreCase) ||
                                          result.FilePath.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase) ||
                                          result.FilePath.Contains(@"\Masaüstü\", StringComparison.OrdinalIgnoreCase);

                    // İmzasız, kullanıcı indirme/çalışma alanında ve şüpheli PE entropisi/packer anomalisi taşıyan ikili
                    if (isUserWorkArea && (result.Entropy >= 6.0 || result.IsPacked))
                    {
                        isPup = true;
                        pupReason = "+50 Potansiyel İstenmeyen / Korsan Yazılım (PUP/Crack/Keygen) davranış kalıbı (İmzasız, Kullanıcı Alanı ve PE Entropi/Paket Anomalisi)";
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

            // TR: Aşama 4: Shannon entropi ve paketleyici (packer) analizi; şifreli veya sıkıştırılmış PE bölümlerini tespit eder.
            // EN: Stage 4: Shannon entropy and packer heuristics; detects encrypted or compressed PE payload sections.
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

            // TR: Aşama 5: Çift uzantı kamuflaj kontrolü (örn. .pdf.exe veya .docx.scr gibi kullanıcıyı aldatmaya yönelik uzantılar).
            // EN: Stage 5: Double extension disguise detection (e.g., .pdf.exe or .docx.scr disguise patterns).
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

            // TR: Aşama 6: İmzasız çalıştırılabilir dosya risk cezası (yalnızca güvenilir olmayan yollardaki ikililer için).
            // EN: Stage 6: Unsigned executable risk penalty (only applied to binaries outside trusted system/app folders).
            // 6. Unsigned Executable Penalty (Only outside of known system/installed app/game directories)
            if (!result.IsSigned && result.IsExecutable && !result.IsKnownLocation && !isInstalledAppFolder && !isGameOrRepack)
            {
                score += 10;
                reasons.Add("+10 Yürütülebilir dosya dijital olarak imzalanmamış");
            }

            // TR: Aşama 7: Çoklu sinyalli şüpheli Win32 API ve davranışsal gösterge analizi (Bellek Enjeksiyonu, Process Hollowing).
            // EN: Stage 7: Multi-signal suspicious Win32 API and behavioral indicator analysis (Process Injection, Process Hollowing).
            // 7. Multi-Signal Suspicious Win32 API & Behavioral Indicators (Only for unsigned binaries in untrusted paths)
            bool isKnownSafe = result.IsKnownLocation || PathHelper.IsKnownSafePath(result.FilePath);
            if (!result.IsSigned && !isKnownSafe && !string.IsNullOrEmpty(result.FilePath) && File.Exists(result.FilePath))
            {
                var apis = await MalwareSignatureDatabase.ScanApiIndicatorsAsync(result.FilePath, cancellationToken);
                bool hasInjectionOrHollowing = false;
                foreach (var api in apis)
                {
                    // Oyun ve crack dosyalarında bellek hook'lama (VirtualAllocEx, SetWindowsHookEx) doğal olduğundan ağırlık hafifletilir
                    int effectiveWeight = isGameOrRepack ? Math.Max(2, api.Weight / 4) : api.Weight;
                    score += effectiveWeight;
                    reasons.Add($"+{effectiveWeight} API Göstergesi: {api.Description}" + (isGameOrRepack ? " (Oyun Modu İndirimi)" : ""));

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
                if (hasInjectionOrHollowing && !isGameOrRepack && !reasons.Any(r => r.Contains("PUP")))
                {
                    score += 20;
                    reasons.Add("+20 PE Davranışsal Gösterge: Bellek enjeksiyonu veya Process Hollowing API tespiti");
                }
            }

            // TR: Aşama 8: Microsoft imzalı güvenilir ikililer için LOLBin koruması ve skorun 0-100 aralığına sınırlandırılması.
            // EN: Stage 8: LOLBin mitigation for Microsoft-signed binaries and score clamping between 0 and 100.
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
