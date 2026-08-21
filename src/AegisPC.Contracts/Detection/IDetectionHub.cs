using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Detection
{
    public interface IDetectorPlugin
    {
        string DetectorId { get; }
        string DisplayName { get; }
        EvidenceCategory PrimaryCategory { get; }
        int Priority { get; } // Lower = executed earlier (Fast path)
        bool IsEnabled { get; set; }

        Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default);
    }

    public interface IDetectionHub
    {
        IReadOnlyList<IDetectorPlugin> RegisteredDetectors { get; }
        void RegisterDetector(IDetectorPlugin detector);
        bool UnregisterDetector(string detectorId);

        Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default);
    }
}
