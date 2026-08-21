using System;
using System.Collections.Generic;
using AegisPC.Core.Models;

namespace AegisPC.Contracts.Behavior
{
    /// <summary>
    /// Belirli bir zamansal pencere içerisinde gerçekleşen davranış olaylarını (Behavior Events)
    /// MITRE ATT&CK aşamalarına göre korele eden saldırı zinciri motoru arayüzü.
    /// </summary>
    public interface IAttackChainCorrelator
    {
        void RecordEvent(BehaviorEvent evt);
        AttackChainCorrelationResult EvaluateChain(int pid, TimeSpan slidingWindow);
        IReadOnlyList<AttackChainCorrelationResult> GetActiveAttackChains(TimeSpan slidingWindow);
        void ClearHistory();
    }
}
