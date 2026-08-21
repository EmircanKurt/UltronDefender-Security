using System.Collections.Generic;
using AegisPC.Contracts.Detection;

namespace AegisPC.Contracts.Behavior
{
    public enum ProcessInjectionTechnique
    {
        None = 0,
        RemoteThreadInjection = 1,
        ProcessHollowing = 2,
        EarlyBirdApcInjection = 3,
        ModuleStomping = 4,
        SuspiciousCrossProcessMemoryWrite = 5
    }

    public class ProcessInjectionEvaluation
    {
        public bool IsInjectionDetected { get; set; }
        public ProcessInjectionTechnique Technique { get; set; } = ProcessInjectionTechnique.None;
        public int SourcePid { get; set; }
        public int TargetPid { get; set; }
        public string SourceProcessName { get; set; } = string.Empty;
        public string TargetProcessName { get; set; } = string.Empty;
        public int SeverityScore { get; set; }
        public List<string> ObservedApis { get; set; } = new();
        public List<SecurityEvidence> Evidences { get; set; } = new();
        public string Explanation { get; set; } = string.Empty;

        public override string ToString() => $"[Injection: {IsInjectionDetected}, Technique: {Technique}, Score: {SeverityScore}] {Explanation}";
    }
}
