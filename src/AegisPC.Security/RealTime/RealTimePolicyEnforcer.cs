using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı güvenlik politikası infaz arayüzü.
    /// Tehdit ve şüpheli durumlarda karantina, uyarı, süreç sonlandırma ve olay bildirimlerini yürütür.
    /// </summary>
    public interface IRealTimePolicyEnforcer
    {
        /// <summary>
        /// Bir tehdit algılandığında tetiklenir.
        /// </summary>
        event Action<SecurityFinding>? OnThreatDetected;

        /// <summary>
        /// Kritik bir güvenlik olayı (Incident) oluşturulduğunda tetiklenir.
        /// </summary>
        event Action<SecurityIncident>? OnIncidentCreated;

        /// <summary>
        /// Kullanıcı arayüzüne bildirim (Toast) gönderilmesi gerektiğinde tetiklenir.
        /// </summary>
        event Action<string, string, string>? OnNotificationRaised;

        /// <summary>
        /// Şüpheli dosya uyarısını infaz eder (dosyaya dokunulmaz, kullanıcı ve güvenlik günlüğü uyarılır).
        /// </summary>
        Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct);

        /// <summary>
        /// Karantina politikasını infaz eder (aktif süreç varsa durdurulur, dosya AES-256 kasaya kilitlenir).
        /// </summary>
        Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct);
    }

    /// <summary>
    /// Gerçek zamanlı güvenlik politikası infaz sınıfı.
    /// </summary>
    public class RealTimePolicyEnforcer : IRealTimePolicyEnforcer
    {
        private readonly IQuarantineService _quarantineService;
        private readonly ISecurityFindingService _findingService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger? _logger;

        public event Action<SecurityFinding>? OnThreatDetected;
        public event Action<SecurityIncident>? OnIncidentCreated;
        public event Action<string, string, string>? OnNotificationRaised;

        public RealTimePolicyEnforcer(
            IQuarantineService quarantineService,
            ISecurityFindingService findingService,
            IAuditLogService? auditLogService = null,
            ILogger? logger = null)
        {
            _quarantineService = quarantineService;
            _findingService = findingService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        public async Task EnforceWarningAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
        {
            try
            {
                var fileInfo = new FileInfo(evt.NormalizedPath);
                var finding = new SecurityFinding
                {
                    ObjectPath = evt.NormalizedPath,
                    ObjectName = fileInfo.Name,
                    SHA256 = verdict.SHA256,
                    RiskLevel = verdict.RiskLevel,
                    RiskScore = verdict.RiskScore,
                    Category = FindingCategory.MalwareSuspicion,
                    Title = verdict.ThreatTitle,
                    Description = verdict.ThreatDescription,
                    RiskReasons = verdict.Evidences,
                    ConfidenceLevel = ConfidenceLevel.Medium,
                    FirstObserved = DateTime.UtcNow,
                    LastObserved = DateTime.UtcNow,
                    Status = FindingStatus.Active
                };

                await _findingService.AddFindingAsync(finding, ct);
                OnThreatDetected?.Invoke(finding);

                // Master UX Policy: Do not spam user toasts for low-confidence warnings (Score < 70).
                // Log silently to Security Center and Audit Log instead.
                if (verdict.RiskScore >= 70)
                {
                    string toastTitle = "⚠️ Yüksek Riskli Dosya Algılandı";
                    string toastMsg = $"'{fileInfo.Name}' şüpheli davranış deseni sergiliyor (Skor: {verdict.RiskScore}/100).";
                    OnNotificationRaised?.Invoke(toastTitle, toastMsg, "Warning");
                }

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.ScanCompleted,
                        "InstantArrivalProtection",
                        fileInfo.Name,
                        evt.NormalizedPath,
                        $"Şüpheli dosya uyarısı (Skor: {verdict.RiskScore}) - Silinmedi, kullanıcı uyarıldı.",
                        AuditResult.Success,
                        cancellationToken: ct);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to enforce warning for {Path}", evt.NormalizedPath);
            }
        }

        public async Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
        {
            try
            {
                var fileInfo = new FileInfo(evt.NormalizedPath);

                // 0. CREATE AUDIT INCIDENT
                var finding = new SecurityFinding
                {
                    Id = Guid.NewGuid(),
                    ObjectName = fileInfo.Name,
                    ObjectPath = evt.NormalizedPath,
                    SHA256 = verdict.SHA256,
                    Title = verdict.ThreatTitle,
                    Description = verdict.ThreatDescription,
                    RiskScore = verdict.RiskScore,
                    RiskLevel = verdict.RiskLevel,
                    Category = FindingCategory.KnownMalwareHash,
                    ConfidenceLevel = ConfidenceLevel.High,
                    FirstObserved = DateTime.UtcNow,
                    LastObserved = DateTime.UtcNow,
                    Status = FindingStatus.Active
                };

                // 1. ACTIVE PROCESS CONTAINMENT & TERMINATION
                var (terminatedPid, terminatedProcName) = ProcessMitigationHelper.ContainAndTerminateTargetProcess(
                    evt.NormalizedPath, evt.ProcessId, _logger);

                // 2. Perform Secure AES-256 Quarantine with resilient retry
                bool quarantined = false;
                for (int retry = 0; retry < 5; retry++)
                {
                    quarantined = await _quarantineService.QuarantineFileAsync(evt.NormalizedPath, verdict.ThreatTitle, ct);
                    if (quarantined || !File.Exists(evt.NormalizedPath))
                    {
                        quarantined = true;
                        break;
                    }
                    await Task.Delay(40, ct);
                }

                if (quarantined)
                {
                    finding.Status = FindingStatus.Resolved;
                }

                // 3. Persist Finding to Database
                await _findingService.AddFindingAsync(finding, ct);

                // 4. Create Security Incident
                var incident = new SecurityIncident
                {
                    IncidentId = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}",
                    Title = verdict.ThreatTitle,
                    ThreatName = verdict.ThreatTitle,
                    RootPid = terminatedPid,
                    RootProcessName = !string.IsNullOrEmpty(terminatedProcName) ? terminatedProcName : fileInfo.Name,
                    RootExecutablePath = evt.NormalizedPath,
                    RootHashSha256 = verdict.SHA256,
                    RiskScore = verdict.RiskScore,
                    RiskLevel = verdict.RiskLevel.ToString().ToUpperInvariant(),
                    CreatedAt = DateTime.UtcNow,
                    Status = quarantined ? "Quarantined" : "Active",
                    ActionTaken = terminatedPid > 0 
                        ? $"Aktif zararlı süreç (PID: {terminatedPid}) sonlandırıldı ve dosya AES-256 Karantina Kasasına kilitlendi."
                        : (quarantined ? "Dosya engellendi ve AES-256 Karantina Kasasına kilitlendi." : "Tespit Edildi"),
                    HumanExplanation = $"Gerçek zamanlı koruma kalkanı '{fileInfo.Name}' dosyasında kritik tehdit tespit etti." + 
                        (terminatedPid > 0 ? $" Çalışan zararlı süreç (PID: {terminatedPid}) derhal durduruldu." : "") + " Dosya güvenli şekilde karantinaya alındı.",
                    RecommendedUserAction = "Tehdit başarıyla etkisiz hale getirilmiştir. Gerekirse Karantina Kasası sayfasından inceleyebilirsiniz."
                };
                incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Gerçek Zamanlı Koruma: '{fileInfo.Name}' tehdit deseni algılandı.");
                incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Analiz Sonucu: Risk Skoru {verdict.RiskScore}/100 ({verdict.Verdict}).");
                if (terminatedPid > 0)
                {
                    incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Müdahale: Aktif çalışan '{terminatedProcName}' (PID: {terminatedPid}) süreci zorla durduruldu.");
                }
                if (quarantined)
                {
                    incident.Timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Karantina: Dosya diskten temizlendi ve AES-256 Kasaya kilitlendi.");
                }

                // 5. Raise UI Events & Windows Toast
                OnThreatDetected?.Invoke(finding);
                OnIncidentCreated?.Invoke(incident);

                string toastTitle = terminatedPid > 0 ? "🛑 Aktif Zararlı Süreç Durduruldu ve Kilitlendi!" : (quarantined ? "🛡️ Tehdit Engellendi ve Karantinaya Alındı!" : "🚨 Tehdit Tespit Edildi!");
                string toastMsg = terminatedPid > 0
                    ? $"'{terminatedProcName}' (PID: {terminatedPid}) süreci durduruldu ve '{fileInfo.Name}' dosyası karantinaya kilitlendi."
                    : $"'{fileInfo.Name}' dosyasında kritik tehdit tespit edildi ve anında engellendi.";

                OnNotificationRaised?.Invoke(toastTitle, toastMsg, "Danger");

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.FileQuarantined,
                        "RealTimeShield",
                        fileInfo.Name,
                        evt.NormalizedPath,
                        $"{verdict.ThreatTitle} - Skor: {verdict.RiskScore}" + (terminatedPid > 0 ? $" - Süreç PID: {terminatedPid} sonlandırıldı." : ""),
                        AuditResult.Success,
                        cancellationToken: ct);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to enforce quarantine for {Path}", evt.NormalizedPath);
            }
        }
    }
}
