using System.Collections.Generic;
using AegisPC.Contracts.Detection;

namespace AegisPC.Contracts.AntiEvasion
{
    /// <summary>
    /// Statik ikili veya çalışan süreç üzerinde tespit edilen anti-analiz ve kaçınma (anti-evasion) değerlendirmesi.
    /// </summary>
    public class AntiEvasionEvaluation
    {
        public bool HasEvasionTechniques { get; set; }
        public AntiEvasionTechnique DetectedTechniques { get; set; } = AntiEvasionTechnique.None;
        public int EvasionScore { get; set; }
        public List<string> TechniqueDescriptions { get; set; } = new();
        public List<SecurityEvidence> Evidences { get; set; } = new();
        public string Explanation { get; set; } = string.Empty;

        public override string ToString() => $"[AntiEvasion: {HasEvasionTechniques}, Score: {EvasionScore}, Techniques: {DetectedTechniques}]";
    }
}
