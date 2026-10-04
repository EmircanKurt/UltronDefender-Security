using System.Threading;
using System.Threading.Tasks;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.ServiceContracts;

/// <summary>Correlated requests to the authenticated installed service; a missing reply is a failure.</summary>
public interface IServiceRequestClient
{
    /// <summary>Sends one bounded request and waits for its matching response or deadline.</summary>
    Task<ServiceReply> RequestAsync(ServiceCommandType command, string? payload = null, CancellationToken cancellationToken = default);
}
