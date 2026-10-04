using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services;

public partial class ServiceIpcClient
{
    /// <summary>Reports device observations independently of malware notifications.</summary>
    public event Action<DeviceNotice>? DeviceObserved;
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<ServiceReply>> _pendingOperationRequests = new();

    /// <summary>Cancellation before sending prevents transmission; cancellation after sending makes the action outcome unconfirmed.</summary>
    public async Task<ServiceReply> RequestAsync(ServiceCommandType command, string? payload = null, CancellationToken cancellationToken = default)
    {
        if (!IsConnected || _isDisposed) throw new IOException("The installed protection service is not connected.");
        if (_pendingOperationRequests.Count >= 32) throw new InvalidOperationException("Too many pending service operations.");
        var id = Guid.NewGuid();
        var completion = new TaskCompletionSource<ServiceReply>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingOperationRequests.TryAdd(id, completion)) throw new InvalidOperationException("Request identity collision.");
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
        try
        {
            linked.Token.ThrowIfCancellationRequested();
            await SendFrameAsync(new ServiceCommand { CommandType = command, Payload = payload, RequestId = id, Timestamp = DateTime.UtcNow }, linked.Token);
            return await completion.Task.WaitAsync(TimeSpan.FromSeconds(30), linked.Token);
        }
        catch (TimeoutException exception)
        { throw new TimeoutException("Service acknowledgement timed out; the action may have completed. Refresh the vault before retrying.", exception); }
        finally { _pendingOperationRequests.TryRemove(id, out _); }
    }
}
