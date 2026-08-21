using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.AntiEvasion;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.AntiEvasion
{
    /// <summary>
    /// Statik dosya taramasında ve DetectionHub içinde Anti-Debug, Anti-VM, Indirect Syscall ve
    /// AMSI/ETW Yamalama tekniklerini tespit ederek Explainable Evidence üreten eklenti.
    /// </summary>
    public class AntiEvasionDetectorPlugin : IDetectorPlugin
    {
        private readonly IAntiEvasionDetector _detector;

        public string DetectorId => "AntiEvasionDetector";
        public string DisplayName => "Anti-Analysis & Evasion Heuristic Detector";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.AntiEvasion;
        public int Priority => 35;
        public bool IsEnabled { get; set; } = true;

        public AntiEvasionDetectorPlugin(IAntiEvasionDetector? detector = null)
        {
            _detector = detector ?? new AntiEvasionDetector();
        }

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var evidences = new List<SecurityEvidence>();

            if (string.IsNullOrWhiteSpace(context.FilePath) || !File.Exists(context.FilePath))
            {
                return evidences;
            }

            var eval = await Task.Run(() => _detector.AnalyzeBinary(context.FilePath), cancellationToken);
            if (eval.HasEvasionTechniques)
            {
                foreach (var ev in eval.Evidences)
                {
                    ev.SourceDetector = DetectorId;
                    ev.FilePath = context.FilePath;
                    evidences.Add(ev);
                }
            }

            return evidences;
        }
    }
}
