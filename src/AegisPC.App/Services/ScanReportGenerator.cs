using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.App.Services
{
    /// <summary>
    /// Formats observed scan results without inferring containment from a risk score or claiming that an entire system is safe.
    /// </summary>
    public static class ScanReportGenerator
    {
        /// <summary>
        /// Varsayılan rapor dosya adını üretir: UltronDefender_Rapor_yyyyMMdd_HHmm.txt
        /// </summary>
        public static string GetDefaultReportFileName(DateTime? timestamp = null)
        {
            var dt = timestamp ?? DateTime.Now;
            return $"UltronDefender_Rapor_{dt:yyyyMMdd_HHmm}.txt";
        }

        /// <summary>
        /// Rapor kaydetmek için varsayılan dizini belirler.
        /// Takılı ve hazır durumda çıkarılabilir USB bellek varsa onu, aksi takdirde Masaüstünü önerir.
        /// </summary>
        public static string GetSuggestedInitialDirectory(Func<IEnumerable<DriveInfo>>? drivesProvider = null)
        {
            try
            {
                if (drivesProvider != null)
                {
                    var drives = drivesProvider();
                    var removable = drives.FirstOrDefault(d => d.DriveType == DriveType.Removable && d.IsReady);
                    if (removable != null && Directory.Exists(removable.RootDirectory.FullName))
                    {
                        return removable.RootDirectory.FullName;
                    }
                }
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Could not inspect suggested report drives");
            }

            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (Directory.Exists(desktop))
                {
                    return desktop;
                }
            }
            catch (Exception ex) { Serilog.Log.Warning(ex, "Could not resolve the desktop report directory"); }

            return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        }

        /// <summary>
        /// Returns only evidenced action labels; a resolved incident or high score alone does not prove quarantine.
        /// </summary>
        public static string DetermineActionTaken(SecurityFinding finding, string? explicitAction = null)
        {
            if (!string.IsNullOrWhiteSpace(explicitAction))
            {
                return explicitAction;
            }

            if (finding.Status == FindingStatus.Ignored || finding.IsAllowlisted)
            {
                return "Muaf tutuldu / İzin verildi";
            }

            if (finding.Status == FindingStatus.Resolved)
            {
                return "Olay kapatıldı (karantina doğrulanmadı)";
            }

            return "Uyarıldı / Kullanıcı müdahalesi bekleniyor";
        }

        /// <summary>
        /// Güvenlik bulgusu için açıklama metnini döndürür; açıklama boşsa standart kategori fallback'ini kullanır.
        /// </summary>
        public static string GetDescriptionWithFallback(SecurityFinding finding)
        {
            if (!string.IsNullOrWhiteSpace(finding.Description))
            {
                return finding.Description.Trim();
            }

            return $"{finding.Category} kategorisinde tespit edilen güvenlik bulgusu.";
        }

        /// <summary>
        /// Formats actual finding and coverage counts, explicitly retaining cancelled, failed, or incomplete coverage.
        /// </summary>
        public static string GenerateTextReport(
            DateTime scanDate,
            string duration,
            string scanType,
            int scannedCount,
            IReadOnlyList<SecurityFinding>? findings,
            IReadOnlyDictionary<string, string>? actionOverrides = null,
            int skippedCount = 0,
            int failedCount = 0,
            int timedOutCount = 0,
            string? resourceProfile = null,
            ScanStatus scanStatus = ScanStatus.Completed)
        {
            var safeFindings = findings ?? Array.Empty<SecurityFinding>();
            var sb = new StringBuilder();
            sb.AppendLine("================================================================================");
            sb.AppendLine("            ULTRON DEFENDER TOTAL SECURITY - GÜVENLİK TARAMA RAPORU             ");
            sb.AppendLine("================================================================================");
            sb.AppendLine($"Tarama Tarihi       : {scanDate:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Tarama Süresi       : {duration}");
            sb.AppendLine($"Tarama Tipi         : {scanType}");
            sb.AppendLine($"Tarama Durumu       : {scanStatus}");
            sb.AppendLine($"Taranan Dosya Sayısı: {scannedCount:N0}");

            if (skippedCount > 0)
            {
                sb.AppendLine($"Atlanan Dosyalar   : {skippedCount:N0}");
            }

            if (failedCount > 0 || timedOutCount > 0)
            {
                sb.AppendLine($"Hatalı / Zaman Aşımı: {failedCount:N0} / {timedOutCount:N0}");
            }

            if (!string.IsNullOrWhiteSpace(resourceProfile))
            {
                sb.AppendLine($"Kaynak Profili     : {resourceProfile}");
            }

            bool hasFindings = safeFindings.Count > 0;
            sb.AppendLine($"Genel Durum         : {(hasFindings ? $"⚠️ {safeFindings.Count} Güvenlik Bulgusu Tespit Edildi" : "İncelenen öğelerde bulgu yok")}");
            if (scanStatus != ScanStatus.Completed || failedCount > 0 || timedOutCount > 0 || skippedCount > 0)
                sb.AppendLine("Kapsam Notu         : Tarama kapsamı eksik; iptal edilen, atlanan veya incelenemeyen dosyalar hakkında temiz kararı verilmedi.");
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine();

            if (hasFindings)
            {
                sb.AppendLine($"[TESPİT EDİLEN GÜVENLİK BULGULARI ({safeFindings.Count})]");
                sb.AppendLine();

                int index = 1;
                foreach (var f in safeFindings)
                {
                    string? explicitAction = null;
                    if (actionOverrides != null)
                    {
                        if (!string.IsNullOrEmpty(f.ObjectPath) && actionOverrides.TryGetValue(f.ObjectPath, out var act1))
                        {
                            explicitAction = act1;
                        }
                        else if (!string.IsNullOrEmpty(f.ObjectName) && actionOverrides.TryGetValue(f.ObjectName, out var act2))
                        {
                            explicitAction = act2;
                        }
                    }

                    string actionTaken = DetermineActionTaken(f, explicitAction);
                    string description = GetDescriptionWithFallback(f);

                    string title = !string.IsNullOrWhiteSpace(f.Title)
                        ? f.Title
                        : (!string.IsNullOrWhiteSpace(f.ObjectName)
                            ? f.ObjectName
                            : (!string.IsNullOrWhiteSpace(f.ObjectPath) ? Path.GetFileName(f.ObjectPath) : "Bilinmeyen Tehdit"));

                    string objectPath = !string.IsNullOrWhiteSpace(f.ObjectPath) ? f.ObjectPath : "(Yol Belirtilmemiş / Bellek Tehdidi)";

                    sb.AppendLine($"--- Bulgu #{index} ---");
                    sb.AppendLine($"Tehdit Adı     : {title}");
                    sb.AppendLine($"Risk Skoru     : {f.RiskScore}/100");
                    sb.AppendLine($"Kategori       : {f.Category}");
                    sb.AppendLine($"Dosya Yolu     : {objectPath}");
                    sb.AppendLine($"Alınan Aksiyon : {actionTaken}");
                    sb.AppendLine($"Açıklama       : {description}");
                    sb.AppendLine();
                    index++;
                }
            }
            else
            {
                sb.AppendLine("[TESPİT EDİLEN GÜVENLİK BULGULARI (0)]");
                sb.AppendLine("İncelenen öğelerde güvenlik bulgusu tespit edilmedi. Bu sonuç, tüm sistemin güvenli olduğu garantisi değildir.");
                sb.AppendLine();
            }

            sb.AppendLine("================================================================================");
            sb.AppendLine("Ultron Defender Total Security | Gelişmiş Tehdit Savunma Motoru");

            return sb.ToString();
        }

        /// <summary>Serializes a final engine snapshot including coverage failures and only confirmed action overrides.</summary>
        public static string GenerateJsonReport(ScanReportRecord report)
        {
            ArgumentNullException.ThrowIfNull(report);
            return System.Text.Json.JsonSerializer.Serialize(new
            {
                Application = "Ultron Defender Total Security",
                ExportTimestamp = DateTime.UtcNow,
                report.Id,
                Status = report.Result.Status.ToString(),
                ScanType = report.Result.ScanType.ToString(),
                report.Result.StartedAt,
                report.Result.CompletedAt,
                report.Result.ElapsedMs,
                report.Result.ScannedFiles,
                report.Result.TotalFiles,
                report.Result.SkippedFiles,
                report.Result.FailedFiles,
                report.Result.TimedOutFiles,
                report.ResourceProfile,
                ReportedCoverageComplete = report.Result.Status == ScanStatus.Completed && report.Result.SkippedFiles == 0 && report.Result.FailedFiles == 0 && report.Result.TimedOutFiles == 0,
                CoverageNote = "Only engine-reported counters; not proof that every system path, archive member or running process was inspected.",
                Findings = report.Result.Findings.Select(f => new
                {
                    f.Id, f.Title, f.Description, f.ObjectPath, f.SHA256, f.RiskScore,
                    Category = f.Category.ToString(),
                    Status = f.Status.ToString(),
                    ActionTaken = DetermineActionTaken(f, report.Actions.TryGetValue(f.ObjectPath, out var action) ? action : null)
                })
            }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        }
    }
}
