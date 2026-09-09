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
        public string RootProcessName { get; set; } = string.Empty;
        public string RootExecutablePath { get; set; } = string.Empty;
        public string? RootHashSha256 { get; set; }

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
