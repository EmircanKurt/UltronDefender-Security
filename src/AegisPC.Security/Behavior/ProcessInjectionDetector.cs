using System;
using System.Collections.Generic;
using System.Linq;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Behavior
{
    /// <summary>
    /// Süreçler arası bellek enjeksiyonu (Remote Thread, Process Hollowing, Early Bird APC, Module Stomping)
    /// davranış dizilimlerini analiz eden heuristik tespit motoru.
    /// </summary>
    public class ProcessInjectionDetector : IProcessInjectionDetector
    {
        public ProcessInjectionEvaluation EvaluateApiSequence(
            int sourcePid,
            int targetPid,
            IEnumerable<string> observedApis,
            string sourceProcName = "",
            string targetProcName = "")
        {
            var apiSet = new HashSet<string>(observedApis ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);

            var evaluation = new ProcessInjectionEvaluation
            {
                SourcePid = sourcePid,
                TargetPid = targetPid,
                SourceProcessName = sourceProcName,
                TargetProcessName = targetProcName,
                ObservedApis = apiSet.ToList()
            };

            bool hasVirtualAllocEx = apiSet.Contains("VirtualAllocEx") || apiSet.Contains("NtAllocateVirtualMemory");
            bool hasWriteProcessMemory = apiSet.Contains("WriteProcessMemory") || apiSet.Contains("NtWriteVirtualMemory");
            bool hasCreateRemoteThread = apiSet.Contains("CreateRemoteThread") || apiSet.Contains("NtCreateThreadEx") || apiSet.Contains("RtlCreateUserThread");
            bool hasQueueUserApc = apiSet.Contains("QueueUserAPC") || apiSet.Contains("NtQueueApcThread");
            bool hasUnmapSection = apiSet.Contains("NtUnmapViewOfSection") || apiSet.Contains("ZwUnmapViewOfSection");
            bool hasSetThreadContext = apiSet.Contains("SetThreadContext") || apiSet.Contains("NtSetContextThread");
            bool hasVirtualProtect = apiSet.Contains("VirtualProtectEx") || apiSet.Contains("NtProtectVirtualMemory");

            // 1. Process Hollowing
            // (NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + SetThreadContext)
            if (hasUnmapSection && (hasVirtualAllocEx || hasWriteProcessMemory) && hasSetThreadContext)
            {
                evaluation.IsInjectionDetected = true;
                evaluation.Technique = ProcessInjectionTechnique.ProcessHollowing;
                evaluation.SeverityScore = 95;
                evaluation.Explanation = $"Süreç İçi PE Boşaltma (Process Hollowing): '{sourceProcName}' (PID: {sourcePid}) hedef '{targetProcName}' (PID: {targetPid}) sürecinin belleğini boşaltıp kendi kodunu yerleştirdi.";
                evaluation.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.BehaviorMemory,
                    RuleName = "INJECTION_PROCESS_HOLLOWING",
                    ScoreContribution = 45,
                    Confidence = EvidenceConfidence.High,
                    Description = "NtUnmapViewOfSection + SetThreadContext dizilimi tespit edildi (MITRE T1055.012)."
                });
                return evaluation;
            }

            // 2. Early Bird APC Injection
            // (VirtualAllocEx + WriteProcessMemory + QueueUserAPC)
            if (hasQueueUserApc && (hasVirtualAllocEx || hasWriteProcessMemory))
            {
                evaluation.IsInjectionDetected = true;
                evaluation.Technique = ProcessInjectionTechnique.EarlyBirdApcInjection;
                evaluation.SeverityScore = 90;
                evaluation.Explanation = $"Erken Kod Çalıştırma (Early Bird APC Injection): '{sourceProcName}' hedef sürecin APC kuyruğuna zararlı kabuk kodu enjekte etti.";
                evaluation.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.BehaviorMemory,
                    RuleName = "INJECTION_EARLY_BIRD_APC",
                    ScoreContribution = 40,
                    Confidence = EvidenceConfidence.High,
                    Description = "QueueUserAPC + WriteProcessMemory dizilimi tespit edildi (MITRE T1055.004)."
                });
                return evaluation;
            }

            // 3. Klasik Remote Thread Injection
            // (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
            if (hasCreateRemoteThread && hasVirtualAllocEx && hasWriteProcessMemory)
            {
                evaluation.IsInjectionDetected = true;
                evaluation.Technique = ProcessInjectionTechnique.RemoteThreadInjection;
                evaluation.SeverityScore = 85;
                evaluation.Explanation = $"Uzaktan İş Parçacığı Enjeksiyonu (Remote Thread Injection): '{sourceProcName}' (PID: {sourcePid}) hedef '{targetProcName}' sürecinde harici iş parçacığı başlattı.";
                evaluation.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.BehaviorMemory,
                    RuleName = "INJECTION_REMOTE_THREAD",
                    ScoreContribution = 35,
                    Confidence = EvidenceConfidence.High,
                    Description = "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread dizilimi (MITRE T1055.002)."
                });
                return evaluation;
            }

            // 4. Module Stomping / Phantom DLL Hollowing
            if (hasVirtualProtect && hasWriteProcessMemory && hasSetThreadContext)
            {
                evaluation.IsInjectionDetected = true;
                evaluation.Technique = ProcessInjectionTechnique.ModuleStomping;
                evaluation.SeverityScore = 80;
                evaluation.Explanation = $"Modül Ezme (Module Stomping): '{sourceProcName}' hedef süreçte meşru bir DLL'in bellek alanını ezerek kod çalıştırdı.";
                evaluation.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.BehaviorMemory,
                    RuleName = "INJECTION_MODULE_STOMPING",
                    ScoreContribution = 35,
                    Confidence = EvidenceConfidence.Medium,
                    Description = "VirtualProtectEx + WriteProcessMemory + SetThreadContext dizilimi."
                });
                return evaluation;
            }

            // 5. Şüpheli Süreçler Arası Bellek Yazma (Yalnızca WriteProcessMemory)
            if (hasWriteProcessMemory && sourcePid != targetPid && sourcePid > 0 && targetPid > 0)
            {
                evaluation.IsInjectionDetected = true;
                evaluation.Technique = ProcessInjectionTechnique.SuspiciousCrossProcessMemoryWrite;
                evaluation.SeverityScore = 60;
                evaluation.Explanation = $"Şüpheli Süreç Bellek Erişimi: '{sourceProcName}' hedef '{targetProcName}' sürecinin bellek adres alanına veri yazdı.";
                evaluation.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.BehaviorMemory,
                    RuleName = "SUSPICIOUS_CROSS_PROCESS_WRITE",
                    ScoreContribution = 20,
                    Confidence = EvidenceConfidence.Medium,
                    Description = "Harici süreç adres alanına WriteProcessMemory çağrısı."
                });
                return evaluation;
            }

            return evaluation;
        }
    }
}
