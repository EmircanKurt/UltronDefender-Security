using System;

namespace AegisPC.Core.Exceptions
{
    /// <summary>
    /// Dosya sistemi taraması, kuyruk yönetimi, oturum koordinasyonu veya klasör gezinmesi sırasında oluşan istisna.
    /// </summary>
    [Serializable]
    public class ScanEngineException : AegisSecurityException
    {
        public string? TargetPath { get; }

        public ScanEngineException() { }

        public ScanEngineException(string message) : base(message) { }

        public ScanEngineException(string message, Exception innerException) : base(message, innerException) { }

        public ScanEngineException(string message, string? targetPath, Exception? innerException = null)
            : base(message, innerException!)
        {
            TargetPath = targetPath;
        }
    }
}
