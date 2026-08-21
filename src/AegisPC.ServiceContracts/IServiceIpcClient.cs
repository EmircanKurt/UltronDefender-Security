using System;
using System.Threading.Tasks;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.ServiceContracts
{
    /// <summary>
    /// Service IPC istemci arayüzü — App ile Service arasında Named Pipe haberleşmesi.
    /// </summary>
    public interface IServiceIpcClient : IDisposable
    {
        bool IsConnected { get; }
        Task ConnectAsync();
        Task SendCommandAsync(ServiceCommand command);
        Task<ProtectionStatus> GetStatusAsync();
        
        event Action<ThreatNotification>? ThreatDetected;
        event Action<ProtectionStatus>? StatusChanged;
    }
}
