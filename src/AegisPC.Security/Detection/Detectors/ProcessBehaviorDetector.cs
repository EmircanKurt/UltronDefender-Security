using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Detection.Detectors
{
    public class ProcessBehaviorDetector : IDetectorPlugin
    {
        private readonly IProcessLineageTracker? _lineageTracker;
        private readonly IAttackChainCorrelator? _chainCorrelator;

        public string DetectorId => "Detector.ProcessBehavior";
        public string DisplayName => "Surec Soyagaci ve Davranis Zinciri Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.BehaviorProcess;
        public int Priority => 30;
        public bool IsEnabled { get; set; } = true;

        public ProcessBehaviorDetector(
            IProcessLineageTracker? lineageTracker = null,
            IAttackChainCorrelator? chainCorrelator = null)
        {
            _lineageTracker = lineageTracker;
            _chainCorrelator = chainCorrelator;
        }

        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();

            if (context.ProcessId.HasValue && context.ProcessId.Value > 0 && _lineageTracker != null)
            {
                var pid = context.ProcessId.Value;
                var ppid = context.ParentProcessId.GetValueOrDefault(0);

                // Check LOLBin parent anomaly
                if (_lineageTracker.IsSuspiciousParentChild(ppid, pid, out var anomalyReason))
                {
                    list.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.BehaviorProcess,
                        SourceDetector = DisplayName,
                        RuleName = "Process.SuspiciousLineage",
                        Description = $"Supheli Surec Soyagaci / LOLBin Turemesi: {anomalyReason}",
                        ScoreContribution = 35,
                        Confidence = EvidenceConfidence.High,
                        ProcessId = pid,
                        ParentProcessId = ppid,
                        FilePath = context.FilePath,
                        SHA256 = context.SHA256
                    });
                }
            }

            return Task.FromResult<IEnumerable<SecurityEvidence>>(list);
        }
    }
}
