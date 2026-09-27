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

    /// <summary>Provides the actual quarantine outcome so telemetry never reports an uncommitted action.</summary>
    public interface IRealTimePolicyOutcomeEnforcer
    {
        /// <summary>Returns true only after a confirmed, content-bound quarantine is committed.</summary>
        Task<bool> EnforceQuarantineWithOutcomeAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct);
    }

    /// <summary>
    /// Gerçek zamanlı güvenlik politikası infaz sınıfı.
    /// </summary>
    public class RealTimePolicyEnforcer : IRealTimePolicyEnforcer, IRealTimePolicyOutcomeEnforcer
    {
        private readonly IQuarantineService _quarantineService;
        private readonly ISecurityFindingService _findingService;
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger? _logger;
        private readonly Func<bool> _enableAutoQuarantine;
        private readonly Func<int> _autoQuarantineThreshold;

        public event Action<SecurityFinding>? OnThreatDetected;
        public event Action<SecurityIncident>? OnIncidentCreated;
        public event Action<string, string, string>? OnNotificationRaised;

        public RealTimePolicyEnforcer(
            IQuarantineService quarantineService,
            ISecurityFindingService findingService,
            IAuditLogService? auditLogService = null,
            ILogger? logger = null,
            Func<bool>? enableAutoQuarantine = null,
            Func<int>? autoQuarantineThreshold = null)
        {
            _quarantineService = quarantineService;
            _findingService = findingService;
            _auditLogService = auditLogService;
            _logger = logger;
            _enableAutoQuarantine = enableAutoQuarantine ?? (() => true);
            _autoQuarantineThreshold = autoQuarantineThreshold ?? (() => 85);
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

                // 60-84 arası şüpheli dosyalar için kullanıcı uyarısı oluşturulur
                if (verdict.RiskScore >= 60)
                {
                    string toastTitle = "⚠️ Şüpheli Dosya Uyarısı";
                    string toastMsg = $"'{fileInfo.Name}' şüpheli davranış sergiliyor (Risk Skoru: {verdict.RiskScore}/100).";
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
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "Failed to enforce warning for {Path}", evt.NormalizedPath);
            }
        }

        /// <summary>Compatibility adapter for callers that do not consume action outcomes.</summary>
        public async Task EnforceQuarantineAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
            => await EnforceQuarantineWithOutcomeAsync(evt, verdict, ct);

        /// <summary>Enforces exact, hash-bound findings; unconfirmed or stale findings leave the file intact.</summary>
        public async Task<bool> EnforceQuarantineWithOutcomeAsync(NormalizedFileEvent evt, RealTimeVerdictResult verdict, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!_enableAutoQuarantine() || verdict.RiskScore < Math.Clamp(_autoQuarantineThreshold(), 1, 100))
            {
                await EnforceWarningAsync(evt, verdict, ct);
                return false;
            }
            if (verdict.Verdict != RealTimeVerdict.ConfirmedMalicious ||
                verdict.RecommendedPolicy != RealTimePolicyAction.BlockAndQuarantine ||
                verdict.SHA256.Length != 64 || !System.Linq.Enumerable.All(verdict.SHA256, Uri.IsHexDigit))
            {
                _logger?.LogWarning("Rejected automatic action without an exact, content-bound verdict for {Path}", evt.NormalizedPath);
                return false;
            }
            if (_quarantineService is not IContentBoundQuarantineService contentBound)
            {
                _logger?.LogWarning("Automatic quarantine requires a content-bound vault implementation for {Path}", evt.NormalizedPath);
                return false;
            }
            bool quarantined = false;
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

                // File arrivals do not carry verified process identity. Never terminate a process by
                // a recycled PID or path alone; the ETW observer verifies its captured identity separately.
                int terminatedPid = 0;
                string terminatedProcName = string.Empty;

                // 2. Perform Secure AES-256 Quarantine with resilient retry
                for (int retry = 0; retry < 5; retry++)
                {
                    quarantined = await contentBound.TryQuarantineFileAsync(evt.NormalizedPath, verdict.ThreatTitle, verdict.SHA256, ct);
                    if (quarantined)
                    {
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
                    ActionTaken = quarantined
                        ? (terminatedPid > 0
                            ? $"Aktif zararlı süreç (PID: {terminatedPid}) sonlandırıldı ve dosya AES-256 Karantina Kasasına kilitlendi."
                            : "Dosya engellendi ve AES-256 Karantina Kasasına kilitlendi.")
                        : (terminatedPid > 0
                            ? $"Aktif süreç (PID: {terminatedPid}) sonlandırıldı; dosya karantinası başarısız oldu."
                            : "Tehdit tespit edildi; karantina başarısız oldu."),
                    HumanExplanation = $"Gerçek zamanlı koruma kalkanı '{fileInfo.Name}' dosyasında kritik tehdit tespit etti." + 
                        (terminatedPid > 0 ? $" Çalışan süreç (PID: {terminatedPid}) derhal durduruldu." : "") +
                        (quarantined ? " Dosya güvenli şekilde karantinaya alındı." : " Dosya karantinaya alınamadı ve yeniden incelenmelidir."),
                    RecommendedUserAction = quarantined
                        ? "Tehdit başarıyla etkisiz hale getirilmiştir. Gerekirse Karantina Kasası sayfasından inceleyebilirsiniz."
                        : "Dosya kullanımda veya erişim engelli olabilir. Yönetici yetkisiyle yeniden tarayın ve dosyayı çalıştırmayın."
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

                string toastTitle = quarantined
                    ? (terminatedPid > 0 ? "🛑 Aktif Zararlı Süreç Durduruldu ve Kilitlendi!" : "🛡️ Tehdit Engellendi ve Karantinaya Alındı!")
                    : "🚨 Tehdit Tespit Edildi — Karantina Başarısız!";
                string toastMsg = quarantined
                    ? (terminatedPid > 0
                        ? $"'{terminatedProcName}' (PID: {terminatedPid}) süreci durduruldu ve '{fileInfo.Name}' dosyası karantinaya kilitlendi."
                        : $"'{fileInfo.Name}' dosyası karantinaya alındı.")
                    : $"'{fileInfo.Name}' dosyası karantinaya alınamadı; dosyayı çalıştırmayın ve yeniden tarayın.";

                OnNotificationRaised?.Invoke(toastTitle, toastMsg, "Danger");

                if (_auditLogService != null)
                {
                    await _auditLogService.LogActionAsync(
                        AuditAction.FileQuarantined,
                        "RealTimeShield",
                        fileInfo.Name,
                        evt.NormalizedPath,
                        $"{verdict.ThreatTitle} - Skor: {verdict.RiskScore}" + (terminatedPid > 0 ? $" - Süreç PID: {terminatedPid} sonlandırıldı." : ""),
                        quarantined ? AuditResult.Success : AuditResult.Failed,
                        cancellationToken: ct);
                }
                return quarantined;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to enforce quarantine for {Path}", evt.NormalizedPath);
                return quarantined;
            }
        }
    }
}
