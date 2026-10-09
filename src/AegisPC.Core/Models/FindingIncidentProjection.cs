using System;
using System.Collections.Generic;
using AegisPC.Core.Enums;

namespace AegisPC.Core.Models;

/// <summary>Projects static file observations without inventing actors, probabilities or successful containment.</summary>
public static class FindingIncidentProjection
{
    /// <summary>Builds a review-only incident; a resolved finding is not an action receipt or malware proof.</summary>
    public static SecurityIncident Create(SecurityFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        bool legacy = string.IsNullOrWhiteSpace(finding.RuleSetVersion);
        bool reviewed = finding.Status == FindingStatus.Resolved || finding.IsAllowlisted;
        string provenance = legacy ? "Eski kural sürümü; yeniden değerlendirme gerekli."
            : $"Kural sürümü: {finding.RuleSetVersion}.";
        string coverage = finding.InspectionComplete ? "İçerik incelemesi tamamlandı."
            : "İçerik incelemesi kısmi veya doğrulanamadı; temiz sonucu değildir.";
        return new SecurityIncident
        {
            IncidentId = $"FIND-{finding.Id:N}".ToUpperInvariant(), CreatedAt = finding.CreatedAt,
            Title = finding.Title, ThreatName = finding.Title,
            RootProcessName = "İlişkilendirilmedi", ActorIdentityStatus = "Unknown",
            RootExecutablePath = finding.ObjectPath, RootHashSha256 = finding.SHA256,
            RiskScore = finding.RiskScore, RiskLevel = finding.RiskLevel.ToString().ToUpperInvariant(),
            Status = reviewed ? "Reviewed" : finding.Status == FindingStatus.Ignored ? "Ignored" : "ObservationOnly",
            ActionTaken = reviewed ? "İnceleme durumu güncellendi; müdahale makbuzu yok" : "İnceleme bekleniyor; otomatik müdahale yok",
            HumanExplanation = $"Dosya inceleme kaydı. {finding.Description} {provenance} {coverage} " +
                string.Join("; ", finding.CoverageLimitations),
            RecommendedUserAction = "Kanıtları inceleyin ve güncel kurallarla yeniden tarayın. Sezgisel puan tek başına silme veya karantina yetkisi vermez.",
            Timeline = new List<string>
            {
                $"{finding.CreatedAt:HH:mm:ss} | [Dosya gözlemi] {finding.Category}",
                $"{finding.CreatedAt:HH:mm:ss} | [İnceleme puanı] {finding.RiskScore}/100; zararlılık olasılığı değildir.",
                $"{finding.CreatedAt:HH:mm:ss} | [Kapsam] {provenance} {coverage}"
            },
            Evidences = new List<BehaviorEvidence>
            {
                new() { Type = "StaticFileObservation", Source = finding.ObjectPath, Target = finding.Title,
                    Explanation = finding.Description, Severity = finding.RiskScore, Confidence = 0,
                    ObservationSource = finding.RuleSetVersion }
            }
        };
    }
}
