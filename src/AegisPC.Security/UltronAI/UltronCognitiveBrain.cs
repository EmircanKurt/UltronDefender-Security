using AegisPC.Contracts.Detection;
using AegisPC.Core.Models;

namespace AegisPC.Security.UltronAI;

/// <summary>Explains static observations without claiming malware, MITRE execution or a clean machine.</summary>
public static class UltronCognitiveBrain
{
    /// <summary>Static anomalies can request review, but never authorize blocking or automatic quarantine.</summary>
    public static UltronAiVerdict Reason(UltronFeatureVector vector, UltronDecisionEnsemble.EnsembleOutput output)
        => new()
        {
            Verdict = output.RawRiskScore >= 25 ? DetectionVerdict.Suspicious : DetectionVerdict.Unknown,
            CalculatedRiskScore = output.RawRiskScore,
            MalwareProbability = null,
            Coverage = vector.Coverage,
            CoverageLimitations = vector.CoverageLimitations.ToList(),
            TriggeredAnomalies = output.AnomalySignals,
            RequiresImmediateBlock = false,
            PrimaryDiagnosis = output.RawRiskScore >= 25 ? "İnceleme önerisi; zararlılık doğrulanmadı" : "Kesin zararlı kanıtı yok; temiz garantisi değil",
            ReasoningDeduction = vector.Coverage is ContentClassificationCoverage.Unknown or ContentClassificationCoverage.Partial
                ? "İnceleme kısmi veya veri eksik. Statik öncelik puanı olasılık değildir ve otomatik müdahale yetkisi vermez."
                : "Yalnız yapılandırılmış statik özellikler incelendi; davranış yürütülmedi ve zararlılık doğrulanmadı."
        };
}
