using System;

namespace AegisPC.Core.Exceptions
{
    /// <summary>
    /// Güvenlik politikaları, DPAPI şifrelenmiş ayarlar veya yapılandırma dosyalarının yüklenmesi/kaydedilmesi sırasında oluşan istisna.
    /// </summary>
    [Serializable]
    public class ConfigurationException : AegisSecurityException
    {
        public string? ConfigurationKey { get; }

        public ConfigurationException() { }

        public ConfigurationException(string message) : base(message) { }

        public ConfigurationException(string message, Exception innerException) : base(message, innerException) { }

        public ConfigurationException(string message, string? configurationKey, Exception? innerException = null)
            : base(message, innerException!)
        {
            ConfigurationKey = configurationKey;
        }
    }
}
