using System;
using System.Collections.Generic;

namespace AegisPC.Core.Models
{
    public enum BehaviorEventType
    {
        ProcessSpawn,
        ChildProcessSpawn,
        RegistryPersistence,
        BrowserDataAccess,
        SuspiciousNetworkConnect,
        CredentialAccessAttempt,
        FileEncryptionAttempt,
        ShadowCopyDeletion,
        AmsiBypassAttempt,
        ProcessInjection
    }

    public class BehaviorEvent
    {
        public string EventId { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public BehaviorEventType EventType { get; set; }
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ExecutablePath { get; set; } = string.Empty;
        public string? CommandLine { get; set; }
        public int ParentProcessId { get; set; }
        public string? ParentProcessName { get; set; }
        public string TargetResource { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public double RiskWeight { get; set; } = 10.0;
    }

    public class BehaviorEvidence
    {
        public string EvidenceId { get; set; } = Guid.NewGuid().ToString("N");
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string Type { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public string Explanation { get; set; } = string.Empty;
        public double Confidence { get; set; } = 0.9;
        public int Severity { get; set; } = 50;
    }

    public class SecurityIncident
    {
        public string IncidentId { get; set; } = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string Title { get; set; } = string.Empty;
        public string ThreatName { get; set; } = string.Empty;
        public int RootPid { get; set; }
        public string RootProcessName { get; set; } = string.Empty;
        public string RootExecutablePath { get; set; } = string.Empty;
        public string? RootHashSha256 { get; set; }
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "MEDIUM";
        public string Status { get; set; } = "Active"; // Active, Contained, Quarantined, Remediated
        public string ActionTaken { get; set; } = "None";
        public List<BehaviorEvidence> Evidences { get; set; } = new();
        public List<string> Timeline { get; set; } = new();
        public string HumanExplanation { get; set; } = string.Empty;
        public string RecommendedUserAction { get; set; } = string.Empty;
    }
}
