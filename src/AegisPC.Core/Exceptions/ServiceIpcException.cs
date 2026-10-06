using System;

namespace AegisPC.Core.Exceptions
{
    /// <summary>
    /// UI arayüzü ile arka plan Windows servisi arasındaki NamedPipe IPC iletişimi veya komut yürütme sırasında oluşan istisna.
    /// </summary>
    [Serializable]
    public class ServiceIpcException : AegisSecurityException
    {
        public string? PipeName { get; }

        public ServiceIpcException() { }

        public ServiceIpcException(string message) : base(message) { }

        public ServiceIpcException(string message, Exception innerException) : base(message, innerException) { }

        public ServiceIpcException(string message, string? pipeName, Exception? innerException = null)
            : base(message, innerException!)
        {
            PipeName = pipeName;
        }
    }
}
