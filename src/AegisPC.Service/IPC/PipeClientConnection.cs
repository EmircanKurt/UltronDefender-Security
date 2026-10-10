using System.IO;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.IPC;

/// <summary>One bounded writer pump per client prevents slow UI readers from accumulating protection tasks.</summary>
internal sealed class PipeClientConnection : IDisposable
{
    private readonly Channel<string> _outbound = Channel.CreateBounded<string>(new BoundedChannelOptions(64)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.Wait
    });
    private readonly CancellationTokenSource _lifetime;
    private readonly Task _pump;
    private readonly Stream _pipe;
    private int _disposed;

    /// <summary>True only after a command's OS caller identity is authorized for machine-wide controls.</summary>
    public bool MayReceiveMachineThreats { get; set; }
    /// <summary>Cancellation shared by this connection and service shutdown.</summary>
    public CancellationToken LifetimeToken => _lifetime.Token;

    /// <summary>Creates a writer pump whose shutdown is tied to the service and this connection.</summary>
    public PipeClientConnection(StreamWriter writer, Stream pipe, ILogger logger, CancellationToken stoppingToken)
    {
        _pipe = pipe;
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        _pump = PumpAsync(writer, logger);
    }

    /// <summary>Returns false when the client is slow/disconnected; the producer must disconnect it.</summary>
    public bool TrySend(string message) => _outbound.Writer.TryWrite(message);

    /// <summary>Enqueues a response with a five-second backpressure timeout; does not create per-message tasks.</summary>
    public async Task SendAsync(string message)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        await _outbound.Writer.WriteAsync(message, deadline.Token).ConfigureAwait(false);
    }

    private async Task PumpAsync(StreamWriter writer, ILogger logger)
    {
        try
        {
            await foreach (var message in _outbound.Reader.ReadAllAsync(_lifetime.Token).ConfigureAwait(false))
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                await writer.WriteLineAsync(message.AsMemory(), deadline.Token).ConfigureAwait(false);
                await writer.FlushAsync(deadline.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            logger.LogDebug("IPC client writer stopped or timed out.");
        }
        catch (Exception exception)
        {
            logger.LogDebug(exception, "IPC client writer disconnected.");
        }
        finally
        {
            _lifetime.Cancel();
            _outbound.Writer.TryComplete();
            try { await writer.DisposeAsync().ConfigureAwait(false); }
            catch (Exception exception) { logger.LogDebug(exception, "IPC writer cleanup failed after disconnect."); }
            _pipe.Dispose(); // Also unblocks this connection's pending read.
        }
    }

    /// <summary>Stops the pump and releases the transport; pending queue data is not a durable audit log.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _outbound.Writer.TryComplete();
        _lifetime.Cancel();
        _pipe.Dispose();
        _ = _pump.ContinueWith(_ => _lifetime.Dispose(), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }
}
