using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.RealTime
{
    public class ProcessBehaviorSession
    {
        public int RootPid { get; set; }
        public string RootProcessName { get; set; } = string.Empty;
        public string RootExecutablePath { get; set; } = string.Empty;
        public DateTime StartedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;
        public List<BehaviorEvent> Events { get; } = new();
        public HashSet<int> TrackedProcessTree { get; } = new();
        public int CurrentRiskScore { get; set; }
        public bool IsContained { get; set; }
    }

    public class BehaviorEngine : IBehaviorEngine, IDisposable
    {
        private readonly ILogger<BehaviorEngine>? _logger;
        private readonly IQuarantineService? _quarantineService;
        private readonly IProcessLineageTracker _lineageTracker;
        private readonly IAttackChainCorrelator _attackChainCorrelator;
        private readonly IProcessInjectionDetector _injectionDetector;
        private readonly GameCrackWatchdogShield _gameWatchdog = new();
        private readonly ConcurrentDictionary<int, ProcessBehaviorSession> _sessions = new();
        private readonly ConcurrentDictionary<string, SecurityIncident> _incidents = new();
        private readonly object _lock = new();
        private readonly Timer _cleanupTimer;

        public event Action<SecurityIncident>? OnIncidentCreated;
        public event Action<string, string>? OnThreatContained;

        public IProcessLineageTracker LineageTracker => _lineageTracker;
        public IAttackChainCorrelator AttackChainCorrelator => _attackChainCorrelator;
        public IProcessInjectionDetector InjectionDetector => _injectionDetector;

        public BehaviorEngine(
            IQuarantineService? quarantineService = null,
            IProcessLineageTracker? lineageTracker = null,
            IAttackChainCorrelator? attackChainCorrelator = null,
            IProcessInjectionDetector? injectionDetector = null,
            ILogger<BehaviorEngine>? logger = null)
        {
            _quarantineService = quarantineService;
            _lineageTracker = lineageTracker ?? new AegisPC.Security.Behavior.ProcessLineageTracker();
            _attackChainCorrelator = attackChainCorrelator ?? new AegisPC.Security.Behavior.AttackChainCorrelator(_lineageTracker);
            _injectionDetector = injectionDetector ?? new AegisPC.Security.Behavior.ProcessInjectionDetector();
            _logger = logger;
            _cleanupTimer = new Timer(CleanupSessions, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }

        private void CleanupSessions(object? state)
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(10);
            var expiredKeys = _sessions.Where(kvp => kvp.Value.LastActivityAt < cutoff).Select(kvp => kvp.Key).ToList();
            foreach (var key in expiredKeys)
            {
                _sessions.TryRemove(key, out _);
            }
        }

        public void Dispose()
        {
            _cleanupTimer?.Dispose();
        }

        public async Task ProcessEventAsync(BehaviorEvent e, CancellationToken cancellationToken = default)
        {
            if (e == null) return;

            // Self-Protection Guard: Never monitor or contain Ultron Defender's own processes and binaries
            if (e.ProcessId == Environment.ProcessId || 
                (!string.IsNullOrEmpty(e.ExecutablePath) && Scanning.FileScannerService.IsSelfOwnedPath(e.ExecutablePath)))
            {
                return;
            }

            _lineageTracker.RegisterProcess(new AegisPC.Contracts.Behavior.ProcessNode
            {
                Pid = e.ProcessId,
                ParentPid = e.ParentProcessId,
                ProcessName = e.ProcessName,
                ExecutablePath = e.ExecutablePath,
                CommandLine = e.CommandLine ?? string.Empty,
                StartTimeUtc = e.Timestamp
            });

            _attackChainCorrelator.RecordEvent(e);

            // Find or create session for the process tree
            var session = GetOrCreateSession(e);
            if (session.IsContained) return;

            session.LastActivityAt = DateTime.UtcNow;
            session.Events.Add(e);
            session.TrackedProcessTree.Add(e.ProcessId);

            // Correlate attack patterns and calculate dynamic risk score
            var (newScore, evidences, threatTitle) = EvaluateBehaviorChain(session);

            // Enrich with AttackChainCorrelator multi-stage intelligence
            var chainResult = _attackChainCorrelator.EvaluateChain(session.RootPid, TimeSpan.FromSeconds(60));
            if (chainResult.IsConfirmedAttack && chainResult.TotalRiskScore > newScore)
            {
                newScore = chainResult.TotalRiskScore;
                threatTitle = chainResult.ThreatTitle;
                foreach (var ev in chainResult.Evidences)
                {
                    evidences.Add(new BehaviorEvidence
                    {
                        Type = ev.RuleName,
                        Source = session.RootProcessName,
                        Target = ev.Category.ToString(),
                        Explanation = ev.Description,
                        Severity = ev.ScoreContribution * 2,
                        Confidence = 0.95
                    });
                }
            }

            session.CurrentRiskScore = Math.Clamp(newScore, 0, 100);

            _logger?.LogDebug("Behavior evaluation for PID {Pid} ({Name}): Score={Score}", 
                session.RootPid, session.RootProcessName, session.CurrentRiskScore);

            // Risk Threshold Evaluation (HighRisk >= 75 triggers auto-containment)
            if (session.CurrentRiskScore >= 75 && !session.IsContained)
            {
                session.IsContained = true;
                await ContainAndRemediateAsync(session, threatTitle, evidences, cancellationToken);
            }
        }

        private ProcessBehaviorSession GetOrCreateSession(BehaviorEvent e)
        {
            // Check if this event belongs to an existing parent session
            if (e.ParentProcessId > 0 && _sessions.TryGetValue(e.ParentProcessId, out var parentSession))
            {
                parentSession.TrackedProcessTree.Add(e.ProcessId);
                parentSession.LastActivityAt = DateTime.UtcNow;
                _sessions[e.ProcessId] = parentSession;
                return parentSession;
            }

            return _sessions.GetOrAdd(e.ProcessId, pid => new ProcessBehaviorSession
            {
                RootPid = pid,
                RootProcessName = e.ProcessName,
                RootExecutablePath = e.ExecutablePath,
                StartedAt = e.Timestamp,
                LastActivityAt = DateTime.UtcNow,
                TrackedProcessTree = { pid }
            });
        }

        private (int Score, List<BehaviorEvidence> Evidences, string ThreatTitle) EvaluateBehaviorChain(ProcessBehaviorSession session)
        {
            int score = 0;
            var evidences = new List<BehaviorEvidence>();
            string threatTitle = "Şüpheli Davranış Zinciri";

            bool hasSuspiciousChild = false;
            bool hasPersistence = false;
            bool hasBrowserAccess = false;
            bool hasNetworkOutbound = false;
            bool hasRansomwareActivity = false;
            bool hasAmsiBypass = false;

            foreach (var evt in session.Events)
            {
                switch (evt.EventType)
                {
                    case BehaviorEventType.ChildProcessSpawn:
                        var cmd = evt.CommandLine ?? string.Empty;
                        if (cmd.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                            cmd.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            cmd.Contains("downloadstring", StringComparison.OrdinalIgnoreCase) ||
                            cmd.Contains("iex", StringComparison.OrdinalIgnoreCase) ||
                            evt.TargetResource.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                            evt.TargetResource.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                            evt.TargetResource.Contains("certutil", StringComparison.OrdinalIgnoreCase))
                        {
                            hasSuspiciousChild = true;
                            score += 35;
                            evidences.Add(new BehaviorEvidence
                            {
                                Type = "SuspiciousChildProcess",
                                Source = evt.ProcessName,
                                Target = evt.TargetResource,
                                Explanation = $"Şüpheli gizli komut satırı ve alt süreç başlatıldı: {evt.TargetResource} {cmd}",
                                Severity = 70,
                                Confidence = 0.9
                            });
                        }
                        break;

                    case BehaviorEventType.RegistryPersistence:
                        hasPersistence = true;
                        score += 30;
                        evidences.Add(new BehaviorEvidence
                        {
                            Type = "PersistenceRegistry",
                            Source = evt.ProcessName,
                            Target = evt.TargetResource,
                            Explanation = $"Kalıcılık sağlamak için Windows Başlangıç / Run kaydına müdahale edildi: {evt.TargetResource}",
                            Severity = 75,
                            Confidence = 0.95
                        });
                        break;

                    case BehaviorEventType.BrowserDataAccess:
                        hasBrowserAccess = true;
                        score += 35;
                        evidences.Add(new BehaviorEvidence
                        {
                            Type = "BrowserCredentialAccess",
                            Source = evt.ProcessName,
                            Target = evt.TargetResource,
                            Explanation = $"Tarayıcı profili veya parola veri tabanına yetkisiz erişim denemesi: {evt.TargetResource}",
                            Severity = 85,
                            Confidence = 0.95
                        });
                        break;

                    case BehaviorEventType.SuspiciousNetworkConnect:
                        hasNetworkOutbound = true;
                        score += 20;
                        evidences.Add(new BehaviorEvidence
                        {
                            Type = "C2OutboundConnection",
                            Source = evt.ProcessName,
                            Target = evt.TargetResource,
                            Explanation = $"Dış sunucuya şüpheli komut-kontrol bağlantısı kuruldu: {evt.TargetResource}",
                            Severity = 65,
                            Confidence = 0.85
                        });
                        break;

                    case BehaviorEventType.FileEncryptionAttempt:
                    case BehaviorEventType.ShadowCopyDeletion:
                        hasRansomwareActivity = true;
                        score += 60;
                        evidences.Add(new BehaviorEvidence
                        {
                            Type = "RansomwareDestructiveActivity",
                            Source = evt.ProcessName,
                            Target = evt.TargetResource,
                            Explanation = $"Kripto kilit veya Windows Gölge Kopyaları silme eylemi: {evt.Details}",
                            Severity = 95,
                            Confidence = 0.98
                        });
                        break;

                    case BehaviorEventType.AmsiBypassAttempt:
                        hasAmsiBypass = true;
                        score += 45;
                        evidences.Add(new BehaviorEvidence
                        {
                            Type = "DefenseEvasionAmsi",
                            Source = evt.ProcessName,
                            Target = evt.TargetResource,
                            Explanation = "Windows AMSI (Antimalware Scan Interface) bellek yamalama girişimi.",
                            Severity = 90,
                            Confidence = 0.95
                        });
                        break;
                }

                // Game & Crack Watchdog Shield Evaluation for Sandboxed/Game processes
                if (_gameWatchdog.IsGameOrSandboxProcess(session.RootExecutablePath) || _gameWatchdog.IsGameOrSandboxProcess(evt.ExecutablePath))
                {
                    var procPath = !string.IsNullOrWhiteSpace(session.RootExecutablePath) ? session.RootExecutablePath : evt.ExecutablePath;
                    var wd = _gameWatchdog.EvaluateActivity(procPath, evt.TargetResource);
                    if (wd.IsMalicious)
                    {
                        score += wd.RiskScore;
                        threatTitle = wd.ThreatTitle;
                        evidences.Add(new BehaviorEvidence
                        {
                            Type = wd.Verdict.ToString(),
                            Source = evt.ProcessName,
                            Target = evt.TargetResource,
                            Explanation = wd.Description,
                            Severity = wd.RiskScore,
                            Confidence = 0.95
                        });
                    }
                }
            }

            // Multi-Stage Kill Chain Compound Multipliers
            if (hasSuspiciousChild && hasPersistence && hasBrowserAccess)
            {
                score += 30;
                threatTitle = "Trojan:Win32/Infostealer.MultiStage";
            }
            else if (hasRansomwareActivity)
            {
                score += 40;
                threatTitle = "Trojan:Ransom.Win32/BehavioralEncryptor";
            }
            else if (hasAmsiBypass && hasSuspiciousChild)
            {
                score += 25;
                threatTitle = "Exploit:Win32/DefenseEvasion.MemoryPatch";
            }
            else if (hasPersistence && hasNetworkOutbound)
            {
                score += 20;
                threatTitle = "Backdoor:Win32/C2Agent.Persistence";
            }

            return (score, evidences, threatTitle);
        }

        private async Task ContainAndRemediateAsync(
            ProcessBehaviorSession session, 
            string threatTitle, 
            List<BehaviorEvidence> evidences,
            CancellationToken cancellationToken)
        {
            if (session.RootPid == Environment.ProcessId || 
                (!string.IsNullOrEmpty(session.RootExecutablePath) && Scanning.FileScannerService.IsSelfOwnedPath(session.RootExecutablePath)))
            {
                return;
            }

            var timeline = new List<string>();
            timeline.Add($"[{session.StartedAt:HH:mm:ss}] Süreç başlatıldı: {session.RootProcessName} (PID {session.RootPid})");

            foreach (var evt in session.Events)
            {
                timeline.Add($"[{evt.Timestamp:HH:mm:ss}] {evt.EventType}: {evt.TargetResource} ({evt.Details})");
            }

            // 1. Process Tree Termination (Containment)
            int terminatedCount = 0;
            foreach (var pid in session.TrackedProcessTree.ToList())
            {
                try
                {
                    if (pid <= 4 || pid == Environment.ProcessId) continue;
                    using var proc = Process.GetProcessById(pid);
                    if (AegisPC.Core.Constants.CriticalProcesses.IsCriticalProcess(proc.ProcessName)) continue;

                    if (!proc.HasExited)
                    {
                        proc.Kill(entireProcessTree: true);
                        terminatedCount++;
                    }
                }
                catch { }
            }
            timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] İzolasyon: {terminatedCount} aktif süreç ağacı sonlandırıldı.");

            // 2. Quarantine Root Executable if accessible
            bool quarantined = false;
            if (!string.IsNullOrEmpty(session.RootExecutablePath) && File.Exists(session.RootExecutablePath))
            {
                try
                {
                    if (_quarantineService != null)
                    {
                        quarantined = await _quarantineService.QuarantineFileAsync(
                            session.RootExecutablePath, 
                            threatTitle, 
                            cancellationToken);
                        if (quarantined)
                        {
                            timeline.Add($"[{DateTime.UtcNow:HH:mm:ss}] Karantina: Zararlı kaynak dosya şifrelenerek karantina kasasına alındı.");
                        }
                    }
                }
                catch { }
            }

            // 3. Construct Explainable Incident Report
            var explanationBuilder = new StringBuilder();
            explanationBuilder.AppendLine($"**Tehdit Tespiti:** `{threatTitle}`");
            explanationBuilder.AppendLine($"**Kök Süreç:** `{session.RootProcessName}` (PID: {session.RootPid})");
            explanationBuilder.AppendLine($"**Dosya Yolu:** `{session.RootExecutablePath}`");
            explanationBuilder.AppendLine($"**Risk Skoru:** {session.CurrentRiskScore}/100 (KRİTİK TEHDİT)");
            explanationBuilder.AppendLine();
            explanationBuilder.AppendLine("**Tespit Edilen Kötü Amaçlı Adımlar:**");
            foreach (var ev in evidences)
            {
                explanationBuilder.AppendLine($"• {ev.Explanation}");
            }
            explanationBuilder.AppendLine();
            explanationBuilder.AppendLine("**Uygulanan Güvenlik Müdahalesi:**");
            explanationBuilder.AppendLine("• Saldırı zincirindeki tüm süreçler ve alt komut pencereleri derhal sonlandırıldı.");
            if (quarantined)
            {
                explanationBuilder.AppendLine("• Kaynak dosya güvenli karantina kasasına kilitlendi.");
            }

            var incident = new SecurityIncident
            {
                Title = $"Engellendi: {threatTitle}",
                ThreatName = threatTitle,
                RootPid = session.RootPid,
                RootProcessName = session.RootProcessName,
                RootExecutablePath = session.RootExecutablePath,
                RiskScore = session.CurrentRiskScore,
                RiskLevel = "CRITICAL",
                Status = "Contained",
                ActionTaken = quarantined ? "ProcessTerminated + FileQuarantined" : "ProcessTerminated",
                Evidences = evidences,
                Timeline = timeline,
                HumanExplanation = explanationBuilder.ToString(),
                RecommendedUserAction = "Sisteminiz başarıyla korundu. Tarayıcı parolalarınızın ve oturumlarınızın güvende olduğundan emin olmak için tam sistem taraması yapmanız önerilir."
            };

            _incidents[incident.IncidentId] = incident;
            OnIncidentCreated?.Invoke(incident);
            OnThreatContained?.Invoke(session.RootProcessName, threatTitle);
        }

        public Task<List<SecurityIncident>> GetActiveIncidentsAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_incidents.Values.OrderByDescending(i => i.CreatedAt).ToList());
        }

        public Task<SecurityIncident?> GetIncidentByIdAsync(string incidentId, CancellationToken cancellationToken = default)
        {
            _incidents.TryGetValue(incidentId, out var incident);
            return Task.FromResult(incident);
        }

        public Task<bool> RemediateIncidentAsync(string incidentId, CancellationToken cancellationToken = default)
        {
            if (_incidents.TryGetValue(incidentId, out var incident))
            {
                incident.Status = "Remediated";
                return Task.FromResult(true);
            }
            return Task.FromResult(false);
        }
    }
}
