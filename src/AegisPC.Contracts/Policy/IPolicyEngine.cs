using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Policy
{
    /// <summary>
    /// Güvenlik politikası karar eylemi.
    /// </summary>
    public enum PolicyDecisionAction
    {
        Allow,
        Warn,
        AutoQuarantine
    }

    /// <summary>
    /// Politika değerlendirme ve infaz sonucu.
    /// </summary>
    public record PolicyEvaluationResult
    {
        public PolicyDecisionAction Action { get; init; }
        public string Reason { get; init; } = string.Empty;
        public bool IsProtectedBySafetyGuard { get; init; }
        public bool IsMicrosoftSigned { get; init; }
        public bool QuarantinedSuccessfully { get; init; }
    }

    /// <summary>
    /// Merkezi güvenlik politika motoru arayüzü.
    /// Bulguları analiz eder, RiskScore, Tehdit Kategorisi ve SafetyGuard kontrollerine göre
    /// otomatik karantina veya olay merkezi uyarısı kararlarını üretir ve infaz eder.
    /// </summary>
    public interface IPolicyEngine
    {
        /// <summary>
        /// Bulgunun güvenlik politikası kurallarına göre değerlendirilmesi (salt karar üretimi).
        /// </summary>
        PolicyEvaluationResult EvaluateFinding(SecurityFinding finding, string? filePath = null);

        /// <summary>
        /// Bulgunun güvenlik politikası kurallarına göre asenkron değerlendirilmesi (dijital imza kontrolü dahil).
        /// </summary>
        Task<PolicyEvaluationResult> EvaluateFindingAsync(SecurityFinding finding, string? filePath = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Güvenlik politikasını bulguya karşı infaz eder (karantina/uyarı, bildirim, denetim kaydı).
        /// </summary>
        Task<PolicyEvaluationResult> EnforcePolicyAsync(SecurityFinding finding, CancellationToken cancellationToken = default);
    }
}
