using System;

namespace AegisPC.Core.Exceptions
{
    /// <summary>
    /// Ultron Defender güvenlik motorları ve altyapı bileşenleri için temel istisna sınıfı.
    /// </summary>
    [Serializable]
    public class AegisSecurityException : Exception
    {
        public AegisSecurityException() { }

        public AegisSecurityException(string message) : base(message) { }

        public AegisSecurityException(string message, Exception innerException) : base(message, innerException) { }
    }
}
