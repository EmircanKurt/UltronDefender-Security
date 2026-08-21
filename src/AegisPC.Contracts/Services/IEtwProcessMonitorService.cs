using System;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services
{
    public record EtwProcessEvent
    {
        public int ProcessId { get; init; }
        public int ParentProcessId { get; init; }
        public string ImageFileName { get; init; } = string.Empty;
        public string CommandLine { get; init; } = string.Empty;
        public string UserSid { get; init; } = string.Empty;
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    }

    public record EtwThreatAlert
    {
        public string ThreatName { get; init; } = string.Empty;
        public string RuleName { get; init; } = string.Empty;
        public int SeverityScore { get; init; }
        public int ProcessId { get; init; }
        public string ProcessName { get; init; } = string.Empty;
        public string CommandLine { get; init; } = string.Empty;
        public string MitigationAction { get; init; } = string.Empty;
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    }

    public interface IEtwProcessMonitorService : IDisposable
    {
        bool IsRunning { get; }
        event Action<EtwProcessEvent>? ProcessCreated;
        event Action<EtwThreatAlert>? ThreatDetected;
        void Start();
        void Stop();
        EtwThreatAlert? EvaluateCommandLine(int pid, string processName, string commandLine, int parentPid = 0);
    }
}
