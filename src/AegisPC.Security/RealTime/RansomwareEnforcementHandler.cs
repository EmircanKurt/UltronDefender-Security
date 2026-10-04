using System;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Reports ransomware-related observations without inferring authority to contain a process or file.
    /// </summary>
    public interface IRansomwareEnforcementHandler
    {
        /// <summary>Gets verified blocked attempts, excluding unverified observations.</summary>
        int TotalBlockedAttempts { get; }

        /// <summary>Raised for an observation; its process and damage fields require independent evidence.</summary>
        event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;

        /// <summary>Raised for an observation notification, not a claim of successful containment.</summary>
        event Action<string, string, string>? OnNotificationRaised;

        /// <summary>
        /// Reports an observation. The legacy reason, score, and PID arguments do not provide
        /// authenticated process correlation or authoritative malware evidence and cannot authorize mutation.
        /// </summary>
        Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(
            string offendingPath,
            string reason,
            int riskScore,
            int pid = 0,
            Func<string, bool>? isAppAllowed = null,
            DateTime? incidentTimestamp = null);
    }

    /// <summary>
    /// Observation-only compatibility handler. It never resolves processes, terminates a process,
    /// opens an observed path, or requests quarantine from an unverified heuristic observation.
    /// </summary>
    public class RansomwareEnforcementHandler : IRansomwareEnforcementHandler
    {
        private readonly IAuditLogService? _auditLogService;
        private readonly ILogger? _logger;
        private int _observedAlertCount;

        /// <summary>Gets zero because this handler performs no verified blocking operation.</summary>
        public int TotalBlockedAttempts => 0;

        /// <summary>Raised for suspicious activity without asserting process attribution or damage.</summary>
        public event EventHandler<RansomwareAlertEventArgs>? OnRansomwareAttemptDetected;

        /// <summary>Raised for an observation warning; subscriber failures are isolated.</summary>
        public event Action<string, string, string>? OnNotificationRaised;

        /// <summary>
        /// Preserves legacy dependency compatibility. Quarantine and finding services are deliberately
        /// unused because this API does not receive authoritative containment evidence.
        /// </summary>
        public RansomwareEnforcementHandler(
            IQuarantineService? quarantineService = null,
            ISecurityFindingService? findingService = null,
            IAuditLogService? auditLogService = null,
            ILogger? logger = null)
        {
            _ = quarantineService;
            _ = findingService;
            _auditLogService = auditLogService;
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task<RansomwareDamageAssessment?> EvaluateAndContainThreatAsync(
            string offendingPath,
            string reason,
            int riskScore,
            int pid = 0,
            Func<string, bool>? isAppAllowed = null,
            DateTime? incidentTimestamp = null)
        {
            _ = isAppAllowed; // Uncorrelated caller allowlists cannot establish process identity.
            var incidentTime = incidentTimestamp ?? DateTime.UtcNow;
            var observedScore = Math.Clamp(riskScore, 0, 100);
            var observationNumber = Interlocked.Increment(ref _observedAlertCount);
            var assessment = new RansomwareDamageAssessment
            {
                FilesTargeted = 0,
                FilesModified = 0,
                FilesRenamed = 0,
                FilesDeleted = 0,
                FilesBlocked = 0,
                OffendingProcess = "UnknownProcess",
                IncidentTime = incidentTime
            };
            var alert = new RansomwareAlertEventArgs
            {
                OffendingFilePath = offendingPath ?? string.Empty,
                OffendingProcessName = "UnknownProcess",
                OffendingProcessId = 0,
                DetectionReason = $"Unverified observation: {reason}",
                RiskScore = observedScore,
                ProcessTerminated = false,
                FilesAffected = 0,
                Timestamp = incidentTime
            };

            _logger?.LogWarning(
                "Ransomware-related activity observed. Observation={ObservationNumber}, Path={ObservedPath}, " +
                "ReportedPid={ReportedProcessId}, Score={HeuristicScore}, Reason={ReportedReason}, " +
                "ProcessCorrelationVerified={ProcessCorrelationVerified}, ContainmentPerformed={ContainmentPerformed}",
                observationNumber, offendingPath, pid, observedScore, reason, false, false);
            PublishObservation(alert);
            PublishNotification();
            await RecordObservationAsync(alert).ConfigureAwait(false);
            return assessment;
        }

        private void PublishObservation(RansomwareAlertEventArgs alert)
        {
            var observers = OnRansomwareAttemptDetected;
            if (observers == null) return;
            foreach (EventHandler<RansomwareAlertEventArgs> observer in observers.GetInvocationList())
            {
                try { observer(this, CopyObservation(alert)); }
                catch (Exception exception)
                {
                    _logger?.LogWarning(exception,
                        "A ransomware observation subscriber failed; no containment result was changed.");
                }
            }
        }

        private static RansomwareAlertEventArgs CopyObservation(RansomwareAlertEventArgs source) => new()
        {
            OffendingFilePath = source.OffendingFilePath,
            OffendingProcessName = source.OffendingProcessName,
            OffendingProcessId = source.OffendingProcessId,
            DetectionReason = source.DetectionReason,
            RiskScore = source.RiskScore,
            ProcessTerminated = false,
            FilesAffected = 0,
            Timestamp = source.Timestamp
        };

        private void PublishNotification()
        {
            var observers = OnNotificationRaised;
            if (observers == null) return;
            foreach (Action<string, string, string> observer in observers.GetInvocationList())
            {
                try
                {
                    observer("Suspicious file activity observed",
                        "A heuristic observation requires review. Process identity and file damage are unverified. " +
                        "No process was terminated and no file was quarantined or blocked.", "Warning");
                }
                catch (Exception exception)
                {
                    _logger?.LogWarning(exception,
                        "A ransomware notification subscriber failed; no containment result was changed.");
                }
            }
        }

        private async Task RecordObservationAsync(RansomwareAlertEventArgs alert)
        {
            if (_auditLogService == null) return;
            try
            {
                await _auditLogService.LogActionAsync(
                    AuditAction.ThreatObserved,
                    "RansomwareObservation",
                    "UnknownProcess",
                    alert.OffendingFilePath,
                    $"{alert.DetectionReason}; HeuristicScore={alert.RiskScore}; " +
                    "ProcessCorrelationVerified=false; ProcessTerminated=false; FileQuarantined=false; " +
                    "FilesAffected=0; FilesBlocked=0; ContainmentPerformed=false",
                    AuditResult.Success).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                _logger?.LogWarning(exception,
                    "Ransomware observation audit persistence failed; containment was not performed.");
            }
        }

        private static bool IsExplicitlyAllowedProcess(
            string processName,
            string processPath,
            Func<string, bool>? isAppAllowed)
        {
            // Retain the regression seam: a copied process name never grants path-based allowance.
            _ = processName;
            return !string.IsNullOrWhiteSpace(processPath) &&
                   isAppAllowed?.Invoke(processPath) == true;
        }
    }
}
