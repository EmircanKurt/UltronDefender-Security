using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Archive;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Archive
{
    /// <summary>
    /// Statik dosya taramasında ve DetectionHub içinde Zip Bomb, Decompression Bomb ve
    /// arşiv anomalilerini inceleyerek Explainable Evidence üreten eklenti.
    /// </summary>
    public class ArchiveDetectorPlugin : IDetectorPlugin
    {
        private readonly ISecureArchiveEngine _archiveEngine;

        public string DetectorId => "SecureArchiveDetector";
        public string DisplayName => "Secure Archive & Zip Bomb Detector";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.ArchiveAnomaly;
        public int Priority => 25;
        public bool IsEnabled { get; set; } = true;

        public ArchiveDetectorPlugin(ISecureArchiveEngine? archiveEngine = null)
        {
            _archiveEngine = archiveEngine ?? new SecureArchiveEngine();
        }

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var evidences = new List<SecurityEvidence>();

            if (string.IsNullOrWhiteSpace(context.FilePath) || !File.Exists(context.FilePath))
            {
                return evidences;
            }

            var ext = Path.GetExtension(context.FilePath).ToLowerInvariant();
            if (ext is not ".zip" and not ".iso")
            {
                return evidences;
            }

            var verdict = await _archiveEngine.InspectArchiveAsync(context.FilePath, null, cancellationToken);
            if (verdict.IsValidArchive)
            {
                foreach (var ev in verdict.Evidences)
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
