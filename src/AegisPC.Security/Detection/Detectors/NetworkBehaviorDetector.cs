using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Network;

namespace AegisPC.Security.Detection.Detectors
{
    public class NetworkBehaviorDetector : IDetectorPlugin
    {
        private readonly INetworkProcessCorrelator? _networkCorrelator;

        public string DetectorId => "Detector.NetworkBehavior";
        public string DisplayName => "Ag ve C2 Komuta Kontrol Davranis Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.BehaviorNetwork;
        public int Priority => 40;
        public bool IsEnabled { get; set; } = true;

        public NetworkBehaviorDetector(INetworkProcessCorrelator? networkCorrelator = null)
        {
            _networkCorrelator = networkCorrelator;
        }

        public Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();

            if (context.ProcessId.HasValue && context.ProcessId.Value > 0 && _networkCorrelator != null)
            {
                if (context.Properties.TryGetValue("NetworkFlow", out var flowObj) && flowObj is NetworkFlowEvent flow)
                {
                    var verdict = _networkCorrelator.CorrelateFlow(flow);
                    if (verdict.IsSuspicious)
                    {
                        list.AddRange(verdict.Evidences);
                    }
                }
            }

            return Task.FromResult<IEnumerable<SecurityEvidence>>(list);
        }
    }
}
