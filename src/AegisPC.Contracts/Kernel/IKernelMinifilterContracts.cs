using System;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Kernel
{
    public interface IKernelTelemetryEngine
    {
        event Action<KernelFileTelemetryEvent>? OnTelemetryReceived;
        void IngestKernelEvent(KernelFileTelemetryEvent rawEvent);
        string ResolveNtDeviceToDosPath(string ntPath);
    }

    public interface IKernelIpcService : IDisposable
    {
        event Action<KernelIpcMessage>? OnMessageReceived;
        bool IsConnected { get; }
        Task<bool> ConnectAsync(string portName = "\\AegisFltPort", CancellationToken cancellationToken = default);
        Task DisconnectAsync();
        Task<bool> SendReplyAsync(KernelReplyMessage reply, CancellationToken cancellationToken = default);
    }

    public interface IKernelGatingEngine
    {
        Task<KernelGatingDecision> EvaluatePreOpDecisionAsync(KernelIpcMessage request, CancellationToken cancellationToken = default);
    }
}
