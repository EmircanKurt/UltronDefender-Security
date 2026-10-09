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

        /// <summary>Inspects the caller's retained content where available; sampled references cannot prove executed tampering.</summary>
        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var evidences = new List<SecurityEvidence>();
            cancellationToken.ThrowIfCancellationRequested();
            var borrowed = context.SharedScan?.LockedContent;
            if (borrowed == null && (string.IsNullOrWhiteSpace(context.FilePath) || !File.Exists(context.FilePath)))
            {
                context.CoverageLimitations.Add("AntiEvasionSourceUnavailable");
                return evidences;
            }
            byte[] bytes;
            if (borrowed != null)
            {
                long position = borrowed.Position;
                try
                {
                    borrowed.Position = 0;
                    bytes = new byte[(int)System.Math.Min(512 * 1024, borrowed.Length)];
                    int read = await borrowed.ReadAtLeastAsync(bytes, bytes.Length, false, cancellationToken);
                    if (read != bytes.Length) throw new EndOfStreamException("Retained analysis source changed length.");
                }
                finally { borrowed.Position = position; }
            }
            else
            {
                await using var file = new FileStream(context.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, true);
                bytes = new byte[(int)System.Math.Min(512 * 1024, file.Length)];
                int read = await file.ReadAtLeastAsync(bytes, bytes.Length, false, cancellationToken);
                if (read != bytes.Length) throw new EndOfStreamException("Analysis source changed length.");
            }
            if (context.FileSize > bytes.Length) context.CoverageLimitations.Add("AntiEvasionSampleLimit:512KiB");
            var eval = _detector is AntiEvasionDetector native
                ? native.AnalyzeBinary(context.FilePath, bytes, cancellationToken)
                : _detector.AnalyzeBinary(context.FilePath, bytes);
            cancellationToken.ThrowIfCancellationRequested();
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
