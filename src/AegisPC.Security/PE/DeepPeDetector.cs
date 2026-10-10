using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.PE;

namespace AegisPC.Security.PE
{
    /// <summary>
    /// Taşınabilir Yürütülebilir (PE) dosyaların derin başlık, Rich Header, TLS Callback,
    /// Bölüm Anomalileri (W+X) ve Authenticode sertifikalarını inceleyerek DetectionHub için Kanıt (SecurityEvidence) üreten eklenti.
    /// </summary>
    public partial class DeepPeDetector : IDetectorPlugin
    {
        private readonly IDeepPeAnalyzer _peAnalyzer;

        public string DetectorId => "DeepPeDetector";
        public string DisplayName => "Deep PE Header & Certificate Detector";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.StaticPeStructure;
        public int Priority => 30; // Hash (10) ve Pattern (20) dedektörlerinden sonra çalışır
        public bool IsEnabled { get; set; } = true;

        public DeepPeDetector(IDeepPeAnalyzer? peAnalyzer = null)
        {
            _peAnalyzer = peAnalyzer ?? new DeepPeAnalyzer();
        }

        /// <summary>Maps bounded static PE observations and separately verified signature metadata; prefix omissions remain explicit.</summary>
        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var evidences = new List<SecurityEvidence>();

            if (string.IsNullOrWhiteSpace(context.FilePath) || !File.Exists(context.FilePath))
            {
                return evidences;
            }

            var peResult = await _peAnalyzer.AnalyzeAsync(context.FilePath, cancellationToken);
            return BuildEvidence(peResult, context);
        }

        /// <summary>Identical static evidence mapping for locked loose files and bounded archive buffers; signature verification is a separate scope.</summary>
        internal List<SecurityEvidence> BuildEvidence(PeDeepAnalysisResult peResult, DetectionContext context, bool includeCertificate = true)
        {
            var evidences = new List<SecurityEvidence>();
            if (!peResult.IsStaticInspectionComplete)
                context.CoverageLimitations.Add("DeepPeStaticPrefixOnly: bounded 2 MiB PE prefix, remaining structure not inspected by this detector.");
            if (!peResult.IsPeFile)
            {
                return evidences;
            }

            AddTlsEvidence(peResult, context, evidences);
            AddWritableExecutableEvidence(peResult, context, evidences);
            AddPackingEvidence(peResult, context, evidences);
            AddEntropyEvidence(peResult, context, evidences);
            AddImportedApiEvidence(peResult, context, evidences);
            if (includeCertificate) AddCertificateEvidence(peResult, context, evidences);

            return evidences;
        }
    }
}
