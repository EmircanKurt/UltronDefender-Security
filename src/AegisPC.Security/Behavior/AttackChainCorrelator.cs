using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Detection;
using AegisPC.Core.Models;

namespace AegisPC.Security.Behavior
{
    public class AttackChainCorrelator : IAttackChainCorrelator
    {
        private readonly ConcurrentBag<BehaviorEvent> _events = new();
        private readonly IProcessLineageTracker? _tracker;

        public AttackChainCorrelator(IProcessLineageTracker? tracker = null)
        {
            _tracker = tracker;
        }

        public void RecordEvent(BehaviorEvent evt)
        {
            if (evt == null) return;
            _events.Add(evt);
        }

        public AttackChainCorrelationResult EvaluateChain(int pid, TimeSpan slidingWindow)
        {
            var cutoff = DateTime.UtcNow - slidingWindow;
            var relevantEvents = _events
                .Where(e => e.ProcessId == pid && e.Timestamp >= cutoff)
                .OrderBy(e => e.Timestamp)
                .ToList();

            var result = new AttackChainCorrelationResult
            {
                RootPid = pid,
                FirstEventUtc = relevantEvents.Count > 0 ? relevantEvents.First().Timestamp : DateTime.UtcNow,
                LastEventUtc = relevantEvents.Count > 0 ? relevantEvents.Last().Timestamp : DateTime.UtcNow
            };

            var tactics = new List<string>();
            foreach (var evt in relevantEvents)
            {
                string tactic = MapEventTypeToMitreTactic(evt.EventType);
                if (!tactics.Contains(tactic))
                {
                    tactics.Add(tactic);
                }
            }

            result.MitreTactics = tactics;
            result.MatchedSequence = relevantEvents.Select(e => $"{e.Timestamp:HH:mm:ss} - [{e.EventType}] {e.TargetResource}").ToList();

            // Multi-Stage Correlation scoring
            result.TotalRiskScore = Math.Min(100, tactics.Count * 25 + relevantEvents.Count * 10);
            result.IsConfirmedAttack = tactics.Count >= 2 || result.TotalRiskScore >= 80;

            if (result.IsConfirmedAttack)
            {
                result.ThreatTitle = $"Çok Aşamalı Saldırı Zinciri Tespiti ({tactics.Count} MITRE Evresi)";
                result.Explanation = "Süreç kısa zaman aralığında birden fazla zararlı davranış evresi (Execution, Persistence, Defense Evasion, Impact vb.) sergiledi.";
            }

            return result;
        }

        private static string MapEventTypeToMitreTactic(BehaviorEventType type)
        {
            return type switch
            {
                BehaviorEventType.ProcessSpawn or BehaviorEventType.ChildProcessSpawn => "Execution (T1059)",
                BehaviorEventType.AmsiBypassAttempt => "Defense Evasion (T1562.001)",
                BehaviorEventType.ShadowCopyDeletion or BehaviorEventType.FileEncryptionAttempt => "Impact (T1490)",
                BehaviorEventType.RegistryPersistence => "Persistence (T1547.001)",
                BehaviorEventType.CredentialAccessAttempt or BehaviorEventType.BrowserDataAccess => "Credential Access (T1003)",
                BehaviorEventType.SuspiciousNetworkConnect => "Command and Control (T1071)",
                BehaviorEventType.ProcessInjection => "Privilege Escalation (T1055)",
                _ => "Execution (T1059)"
            };
        }

        public IReadOnlyList<AttackChainCorrelationResult> GetActiveAttackChains(TimeSpan slidingWindow)
        {
            var pids = _events.Select(e => e.ProcessId).Distinct().ToList();
            var results = new List<AttackChainCorrelationResult>();

            foreach (int pid in pids)
            {
                var eval = EvaluateChain(pid, slidingWindow);
                if (eval.IsConfirmedAttack || eval.TotalRiskScore >= 50)
                {
                    results.Add(eval);
                }
            }

            return results;
        }

        public void ClearHistory()
        {
            _events.Clear();
        }
    }
}
