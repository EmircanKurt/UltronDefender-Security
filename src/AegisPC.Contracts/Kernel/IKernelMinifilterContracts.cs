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

    public enum KernelDriverStatus
    {
        NotInstalled = 0,
        SimulatedMode = 1,
        ActiveKernelPort = 2,
        ConnectionFailed = 3
    }

    public interface IKernelIpcService : IDisposable
    {
        public const string DefaultPortName = "\\AegisFilterPort";
        public const string LegacyPortName = "\\AegisFltPort";

        event Action<KernelIpcMessage>? OnMessageReceived;
        bool IsConnected { get; }
        KernelDriverStatus DriverStatus { get; }
        Task<bool> ConnectAsync(string portName = DefaultPortName, CancellationToken cancellationToken = default);
        Task DisconnectAsync();
        Task<bool> SendReplyAsync(KernelReplyMessage reply, CancellationToken cancellationToken = default);
    }

    public interface IKernelGatingEngine
    {
        Task<KernelGatingDecision> EvaluatePreOpDecisionAsync(KernelIpcMessage request, CancellationToken cancellationToken = default);
    }
}
