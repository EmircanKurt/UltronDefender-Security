using System;
using System.Collections.Generic;
using AegisPC.Contracts.AntiEvasion;
using AegisPC.Contracts.Archive;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Network;
using AegisPC.Contracts.PE;
using AegisPC.Contracts.Services;
using AegisPC.Security.AntiEvasion;
using AegisPC.Security.Archive;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.PE;
using AegisPC.Security.Scanning;

namespace AegisPC.Security.Detection
{
    public static class DetectionHubFactory
    {
        public static IDetectionHub CreateDefault(
            IHashService? hashService = null,
            ISignatureVerifier? signatureVerifier = null,
            IDeepPeAnalyzer? deepPeAnalyzer = null,
            IAntiEvasionDetector? antiEvasionDetector = null,
            ISecureArchiveEngine? secureArchiveEngine = null,
            IProcessLineageTracker? lineageTracker = null,
            IAttackChainCorrelator? chainCorrelator = null,
            IProcessInjectionDetector? injectionDetector = null,
            IMemoryPatternScanner? memoryScanner = null,
            INetworkProcessCorrelator? networkCorrelator = null)
        {
            var hash = hashService ?? new HashService();
            var sigVerifier = signatureVerifier ?? new SignatureVerifier();
            var deepPe = deepPeAnalyzer ?? new DeepPeAnalyzer();
            var evasion = antiEvasionDetector ?? new AntiEvasionDetector();
            var archive = secureArchiveEngine ?? new SecureArchiveEngine();

            var detectors = new List<IDetectorPlugin>
            {
                new LocationReputationDetector(sigVerifier),
                new AuthenticodeDetector(sigVerifier),
                new HashSignatureDetector(hash),
                new PeStaticDetector(),
                new DeepPeDetector(deepPe),
                new EntropyDetector(),
                new PersistenceDetector(),
                new ScriptHeuristicDetector(),
                new ArchiveDetectorPlugin(archive),
                new AntiEvasionDetectorPlugin(evasion),
                new ProcessBehaviorDetector(lineageTracker, chainCorrelator),
                new MemoryBehaviorDetector(injectionDetector, memoryScanner),
                new NetworkBehaviorDetector(networkCorrelator)
            };

            return new DetectionHub(detectors);
        }
    }
}
