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

    /// <summary>
    /// Reported telemetry for review. Source labels, event IDs, timestamps, and actor metadata are
    /// descriptive inputs; they do not authenticate a process or authorize containment.
    /// </summary>
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

        /// <summary>Gets or sets the collector label used for deduplication and provenance, never as proof of trust.</summary>
        public string Source { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the upstream observation ID. Related features copied from one source event
        /// must retain this value; an absent value falls back to EventId for replay deduplication.
        /// </summary>
        public string? OriginatingEventId { get; set; }

        /// <summary>
        /// Gets or sets the reported process creation time in UTC. Missing or invalid creation identity
        /// leaves actor correlation Unknown; the telemetry Timestamp must never be substituted.
        /// </summary>
        public DateTime? ProcessStartTimeUtc { get; set; }

        /// <summary>
        /// Gets or sets optional reported parent creation time in UTC. A parent PID alone does not
        /// establish ancestry; this observation-only model does not authenticate the reported relationship.
        /// </summary>
        public DateTime? ParentProcessStartTimeUtc { get; set; }
    }

    /// <summary>Describes a reported behavior feature and its provenance without asserting malicious intent.</summary>
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

        /// <summary>Gets or sets the detached telemetry ID that produced this observation.</summary>
        public string SourceEventId { get; set; } = string.Empty;

        /// <summary>Gets or sets the upstream observation ID shared by features derived from the same event.</summary>
        public string OriginatingEventId { get; set; } = string.Empty;

        /// <summary>Gets or sets the reported collector label; a label is not authenticated provenance.</summary>
        public string ObservationSource { get; set; } = string.Empty;
    }

    /// <summary>Displays observed evidence and the actual action status; a heuristic score is not malware proof.</summary>
    public class SecurityIncident : System.ComponentModel.INotifyPropertyChanged
    {
        public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
        }

        private string _status = "Active";
        private string _actionTaken = "None";
        private int _riskScore;
        private string _riskLevel = "MEDIUM";
        private string _title = string.Empty;
        private string _threatName = string.Empty;
        private string _humanExplanation = string.Empty;

        public string IncidentId { get; set; } = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..6].ToUpperInvariant()}";
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public string Title
        {
            get => _title;
            set { if (_title != value) { _title = value; OnPropertyChanged(); } }
        }

        public string ThreatName
        {
            get => _threatName;
            set { if (_threatName != value) { _threatName = value; OnPropertyChanged(); } }
        }

        public int RootPid { get; set; }
        /// <summary>Displays an unavailable actor without fabricating PID zero as a correlated process.</summary>
        public string ActorPidDisplay => RootPid > 0 ? RootPid.ToString(System.Globalization.CultureInfo.InvariantCulture) : "İlişkilendirilmedi";
        public string RootProcessName { get; set; } = string.Empty;
        public string RootExecutablePath { get; set; } = string.Empty;
        public string? RootHashSha256 { get; set; }

        /// <summary>Gets or sets reported creation identity, or null when the actor cannot be correlated.</summary>
        public DateTime? RootProcessStartTimeUtc { get; set; }

        /// <summary>
        /// Gets or sets actor attribution status. Unknown means a reported PID was not correlated;
        /// ReportedCreationIdentity is still caller telemetry and never authorizes mutation.
        /// </summary>
        public string ActorIdentityStatus { get; set; } = "Unknown";

        public int RiskScore
        {
            get => _riskScore;
            set { if (_riskScore != value) { _riskScore = value; OnPropertyChanged(); } }
        }

        public string RiskLevel
        {
            get => _riskLevel;
            set { if (_riskLevel != value) { _riskLevel = value; OnPropertyChanged(); } }
        }

        public string Status
        {
            get => _status;
            set { if (_status != value) { _status = value; OnPropertyChanged(); } }
        }

        public string ActionTaken
        {
            get => _actionTaken;
            set { if (_actionTaken != value) { _actionTaken = value; OnPropertyChanged(); } }
        }

        public List<BehaviorEvidence> Evidences { get; set; } = new();
        public List<string> Timeline { get; set; } = new();

        public string HumanExplanation
        {
            get => _humanExplanation;
            set { if (_humanExplanation != value) { _humanExplanation = value; OnPropertyChanged(); } }
        }

        public string RecommendedUserAction { get; set; } = string.Empty;
    }
}
