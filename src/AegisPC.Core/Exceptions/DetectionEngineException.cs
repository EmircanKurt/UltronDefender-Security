using System;

namespace AegisPC.Core.Exceptions
{
    /// <summary>
    /// Zararlı yazılım dedektörleri, PE analizörü, YARA kural motoru veya sezgisel analiz sırasında oluşan istisna.
    /// </summary>
    [Serializable]
    public class DetectionEngineException : AegisSecurityException
    {
        public string? DetectorName { get; }
        public string? InspectedPath { get; }

        public DetectionEngineException() { }

        public DetectionEngineException(string message) : base(message) { }

        public DetectionEngineException(string message, Exception innerException) : base(message, innerException) { }

        public DetectionEngineException(string message, string? detectorName, string? inspectedPath = null, Exception? innerException = null)
            : base(message, innerException!)
        {
            DetectorName = detectorName;
            InspectedPath = inspectedPath;
        }
    }
}
