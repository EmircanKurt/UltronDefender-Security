using AegisPC.Contracts.Detection;

namespace AegisPC.Security.UltronAI;

/// <summary>Handwritten, family-capped static review rules; neither ML nor a malware probability estimator.</summary>
public static class UltronDecisionEnsemble
{
    /// <summary>Contains a bounded review priority and explanatory static observations.</summary>
    public sealed record EnsembleOutput(int RawRiskScore, List<string> AnomalySignals);

    /// <summary>Does not infer executed behavior from imports or infer trust from a filename, path or signature.</summary>
    public static EnsembleOutput Predict(UltronFeatureVector vector)
    {
        var signals = new List<string>();
        int packing = 0, structure = 0, imports = 0;
        if (vector.EntropyOverall >= 7.2f || vector.EntropyCodeSection >= 7.35f)
        { packing = 20; signals.Add("Yüksek örnek entropisi; sıkıştırılmış meşru yazılımda da görülebilir."); }
        if (vector.HasSuspiciousSectionName)
        { packing = Math.Max(packing, 20); signals.Add("Paketleyici bölüm adı; tek başına zararlılık kanıtı değildir."); }
        if (vector.HasWritableExecutableSection)
        { structure = 20; signals.Add("Yazılabilir ve çalıştırılabilir PE bölümü."); }
        if (vector.SizeRawVsVirtualRatio >= 3f)
        { structure = Math.Max(structure, 15); signals.Add("PE sanal/ham boyut farkı."); }
        if (vector.DangerousApiRatio >= 0.15f || vector.HasProcessInjectionApis)
        { imports = 20; signals.Add("Süreç/bellek API içe aktarımları; çağrıldıkları doğrulanmadı."); }
        if (vector.HasTlsCallbacks && vector.HasAntiDebuggingApis)
        { imports = Math.Max(imports, 15); signals.Add("TLS yapısı ve hata ayıklama API içe aktarımları."); }
        return new(Math.Min(60, packing + structure + imports), signals);
    }
}
