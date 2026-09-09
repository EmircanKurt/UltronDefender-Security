using System;
using AegisPC.Core.Helpers;
using AegisPC.Service.Network;

namespace AegisPC.Service.SmartScreen
{
    /// <summary>
    /// Service katmanı için Mark of the Web (MOTW) analizcisi.
    /// Core.Helpers.MotwAnalyzer ve ZoneIdentifierAnalyzer yeteneklerini birleştirir.
    /// </summary>
    public class MotwAnalyzer
    {
        private readonly ZoneIdentifierAnalyzer _zoneAnalyzer;

        public MotwAnalyzer(UrlBlocklistManager? blocklistManager = null)
        {
            _zoneAnalyzer = new ZoneIdentifierAnalyzer(blocklistManager);
        }

        public ZoneAnalysisResult Analyze(string filePath)
        {
            return _zoneAnalyzer.AnalyzeFile(filePath);
        }

        public MotwInfo GetLegacyMotwInfo(string filePath)
        {
            return Core.Helpers.MotwAnalyzer.GetMotwInfo(filePath);
        }

        public bool UnblockFile(string filePath)
        {
            return _zoneAnalyzer.StripZoneIdentifier(filePath);
        }
    }
}
