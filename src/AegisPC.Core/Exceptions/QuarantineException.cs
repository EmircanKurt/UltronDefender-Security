using System;

namespace AegisPC.Core.Exceptions
{
    /// <summary>
    /// Karantina kasası, dosya izolasyonu, şifreleme veya geri yükleme işlemleri sırasında oluşan istisna.
    /// </summary>
    [Serializable]
    public class QuarantineException : AegisSecurityException
    {
        public string? TargetFilePath { get; }
        public string? QuarantineId { get; }

        public QuarantineException() { }

        public QuarantineException(string message) : base(message) { }

        public QuarantineException(string message, Exception innerException) : base(message, innerException) { }

        public QuarantineException(string message, string? targetFilePath, string? quarantineId = null, Exception? innerException = null)
            : base(message, innerException!)
        {
            TargetFilePath = targetFilePath;
            QuarantineId = quarantineId;
        }
    }
}
