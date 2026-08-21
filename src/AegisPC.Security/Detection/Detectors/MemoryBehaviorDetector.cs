using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.AntiEvasion;
using AegisPC.Contracts.Behavior;
using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Detection.Detectors
{
    public class MemoryBehaviorDetector : IDetectorPlugin
    {
        private readonly IProcessInjectionDetector? _injectionDetector;
        private readonly IMemoryPatternScanner? _memoryScanner;

        public string DetectorId => "Detector.MemoryBehavior";
        public string DisplayName => "Bellek Enjeksiyonu ve Kabuk Kodu Analizoru";
        public EvidenceCategory PrimaryCategory => EvidenceCategory.BehaviorMemory;
        public int Priority => 35;
        public bool IsEnabled { get; set; } = true;

        public MemoryBehaviorDetector(
            IProcessInjectionDetector? injectionDetector = null,
            IMemoryPatternScanner? memoryScanner = null)
        {
            _injectionDetector = injectionDetector;
            _memoryScanner = memoryScanner;
        }

        public async Task<IEnumerable<SecurityEvidence>> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            var list = new List<SecurityEvidence>();

            if (context.ProcessId.HasValue && context.ProcessId.Value > 0)
            {
                var pid = context.ProcessId.Value;

                // 1. Process Injection Evaluation via Observed APIs if present in Properties
                if (_injectionDetector != null && context.Properties.TryGetValue("ObservedApis", out var apisObj) && apisObj is IEnumerable<string> apis)
                {
                    var eval = _injectionDetector.EvaluateApiSequence(context.ParentProcessId.GetValueOrDefault(0), pid, apis, context.ProcessName ?? "", context.ProcessName ?? "");
                    if (eval.IsInjectionDetected)
                    {
                        if (eval.Evidences.Count > 0)
                        {
                            list.AddRange(eval.Evidences);
                        }
                        else
                        {
                            list.Add(new SecurityEvidence
                            {
                                Category = EvidenceCategory.BehaviorMemory,
                                SourceDetector = DisplayName,
                                RuleName = $"Memory.Injection.{eval.Technique}",
                                Description = $"Bellek Enjeksiyonu Tespiti ({eval.Technique}): {eval.Explanation}",
                                ScoreContribution = eval.SeverityScore > 0 ? eval.SeverityScore : 50,
                                Confidence = EvidenceConfidence.Absolute,
                                ProcessId = pid,
                                ParentProcessId = context.ParentProcessId,
                                FilePath = context.FilePath,
                                SHA256 = context.SHA256
                            });
                        }
                    }
                }

                // 2. Memory Pattern / Shellcode Scanning
                if (_memoryScanner != null)
                {
                    try
                    {
                        var mv = await _memoryScanner.ScanProcessMemoryAsync(pid, cancellationToken);
                        if (mv.IsMaliciousMemoryFound)
                        {
                            if (mv.Evidences.Count > 0)
                            {
                                list.AddRange(mv.Evidences);
                            }
                            else
                            {
                                list.Add(new SecurityEvidence
                                {
                                    Category = EvidenceCategory.BehaviorMemory,
                                    SourceDetector = DisplayName,
                                    RuleName = $"Memory.Pattern.{mv.MatchedPattern}",
                                    Description = $"Bellekte Bilinen Zararli Kabuk Kodu / Stager Deseni: {mv.ThreatTitle}",
                                    ScoreContribution = mv.SeverityScore > 0 ? mv.SeverityScore : 45,
                                    Confidence = EvidenceConfidence.High,
                                    ProcessId = pid,
                                    ParentProcessId = context.ParentProcessId,
                                    FilePath = context.FilePath,
                                    SHA256 = context.SHA256
                                });
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }

            return list;
        }
    }
}
