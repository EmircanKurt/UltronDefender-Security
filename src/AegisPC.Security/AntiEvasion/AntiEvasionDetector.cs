using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using AegisPC.Contracts.AntiEvasion;
using AegisPC.Contracts.Detection;
using Microsoft.Extensions.Logging;

namespace AegisPC.Security.AntiEvasion
{
    /// <summary>
    /// Statik ikili ve süreç davranışlarında anti-debug, anti-vm, indirect syscall ve
    /// AMSI/ETW yamalama kaçınma tekniklerini tespit eden derin sezgisel motor.
    /// </summary>
    public class AntiEvasionDetector : IAntiEvasionDetector
    {
        private readonly ILogger<AntiEvasionDetector>? _logger;

        private static readonly (string ApiName, int Score, string Description)[] AntiDebugApis = new[]
        {
            ("IsDebuggerPresent", 15, "Hata ayıklayıcı varlığını sorgulama (IsDebuggerPresent)"),
            ("CheckRemoteDebuggerPresent", 20, "Harici hata ayıklayıcı tespiti (CheckRemoteDebuggerPresent)"),
            ("NtQueryInformationProcess", 20, "ProcessDebugPort / DebugFlags sorgulama"),
            ("NtSetInformationThread", 25, "İş parçacığını hata ayıklayıcıdan gizleme (ThreadHideFromDebugger)"),
            ("OutputDebugStringA", 10, "GetLastStatus tabanlı hata ayıklayıcı tespiti (OutputDebugString)")
        };

        private static readonly (string Artifact, int Score, string Description)[] AntiVmArtifacts = new[]
        {
            ("vboxmouse.sys", 25, "VirtualBox sürücü kontrolü"),
            ("vmmouse.sys", 25, "VMware sürücü kontrolü"),
            ("qemu-ga.exe", 25, "QEMU Konuk Ajanı tespiti"),
            ("HARDWARE\\DESCRIPTION\\System\\BIOS", 20, "Sanal makine BIOS üreticisi sorgusu"),
            ("00:05:69", 20, "VMware MAC adresi ön eki"),
            ("08:00:27", 20, "VirtualBox MAC adresi ön eki"),
            ("00:50:56", 20, "VMware MAC adresi ön eki")
        };

        private static readonly (string Pattern, int Score, string Description)[] AmsiEtwBypassSignatures = new[]
        {
            ("amsiInitFailed", 35, "PowerShell AMSI başlatma hatası zorlama (amsiInitFailed)"),
            ("AmsiUtils", 30, "System.Management.Automation.AmsiUtils yansıma erişimi"),
            ("AmsiScanBuffer", 30, "AmsiScanBuffer adresine bellek yamalama hazırlığı"),
            ("EtwEventWrite", 30, "Windows Olay Günlüğü (ETW) susturma yamalaması")
        };

        // Indirect Syscall Stubs: mov r10, rcx (4C 8B D1) -> mov eax, XX (B8 XX XX XX XX) -> syscall (0F 05) -> ret (C3)
        private static readonly byte[] SyscallPatternPrefix = new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 };
        private static readonly byte[] SyscallPatternSuffix = new byte[] { 0x0F, 0x05, 0xC3 };

        public AntiEvasionDetector(ILogger<AntiEvasionDetector>? logger = null)
        {
            _logger = logger;
        }

        public AntiEvasionEvaluation AnalyzeBinary(string filePath, byte[]? rawBytes = null)
        {
            var result = new AntiEvasionEvaluation();

            try
            {
                byte[] bytes = rawBytes ?? (File.Exists(filePath) ? File.ReadAllBytes(filePath) : Array.Empty<byte>());
                if (bytes.Length == 0) return result;

                string asciiContent = Encoding.ASCII.GetString(bytes);

                // 1. Anti-Debug API Tespiti
                int antiDebugCount = 0;
                foreach (var (api, score, desc) in AntiDebugApis)
                {
                    if (asciiContent.Contains(api, StringComparison.OrdinalIgnoreCase))
                    {
                        antiDebugCount++;
                        result.DetectedTechniques |= AntiEvasionTechnique.AntiDebugging;
                        result.TechniqueDescriptions.Add($"Anti-Debug: {api}");
                        result.EvasionScore += score;
                        result.Evidences.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.AntiEvasion,
                            RuleName = $"ANTI_DEBUG_{api.ToUpperInvariant()}",
                            ScoreContribution = score,
                            Confidence = EvidenceConfidence.Medium,
                            Description = desc
                        });
                    }
                }

                // 2. Anti-VM / Sandbox Tespiti
                foreach (var (artifact, score, desc) in AntiVmArtifacts)
                {
                    if (asciiContent.Contains(artifact, StringComparison.OrdinalIgnoreCase))
                    {
                        result.DetectedTechniques |= AntiEvasionTechnique.AntiVmHypervisor;
                        result.TechniqueDescriptions.Add($"Anti-VM: {artifact}");
                        result.EvasionScore += score;
                        result.Evidences.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.AntiEvasion,
                            RuleName = "ANTI_VM_ARTIFACT_CHECK",
                            ScoreContribution = score,
                            Confidence = EvidenceConfidence.High,
                            Description = desc
                        });
                    }
                }

                // 3. AMSI / ETW Bellek Yamalama Desenleri
                foreach (var (pat, score, desc) in AmsiEtwBypassSignatures)
                {
                    if (asciiContent.Contains(pat, StringComparison.OrdinalIgnoreCase))
                    {
                        result.DetectedTechniques |= AntiEvasionTechnique.AmsiEtwPatching;
                        result.TechniqueDescriptions.Add($"AMSI/ETW Patching: {pat}");
                        result.EvasionScore += score;
                        result.Evidences.Add(new SecurityEvidence
                        {
                            Category = EvidenceCategory.AntiEvasion,
                            RuleName = "AMSI_ETW_TAMPERING_PATTERN",
                            ScoreContribution = score,
                            Confidence = EvidenceConfidence.High,
                            Description = desc
                        });
                    }
                }

                // 4. Indirect Syscall Stub Taraması (Statik Byte Taraması)
                if (ContainsIndirectSyscallStub(bytes))
                {
                    result.DetectedTechniques |= AntiEvasionTechnique.IndirectSyscallStubs;
                    result.TechniqueDescriptions.Add("Indirect Syscall: Doğrudan çekirdek çağrı (Hell's Gate / SysWhispers) taslağı");
                    result.EvasionScore += 35;
                    result.Evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.AntiEvasion,
                        RuleName = "INDIRECT_SYSCALL_STUB",
                        ScoreContribution = 35,
                        Confidence = EvidenceConfidence.High,
                        Description = "EDR kancalarını (User-Mode Hooking) atlatmak için doğrudan Syscall yönergesi tespit edildi."
                    });
                }

                result.EvasionScore = Math.Min(100, result.EvasionScore);
                result.HasEvasionTechniques = result.EvasionScore >= 25 || result.DetectedTechniques != AntiEvasionTechnique.None;

                if (result.HasEvasionTechniques)
                {
                    result.Explanation = $"Dosya analizden ve tespitten kaçınmak için {result.TechniqueDescriptions.Count} farklı teknik barındırıyor: {string.Join(", ", result.TechniqueDescriptions)}";
                }
            }
            catch (Exception ex)
            {
                _logger?.LogTrace(ex, "AntiEvasion analysis error for {Path}", filePath);
            }

            return result;
        }

        public AntiEvasionEvaluation AnalyzeBehavior(int pid, string commandLine, IEnumerable<string>? loadedModules = null)
        {
            var result = new AntiEvasionEvaluation();
            if (string.IsNullOrWhiteSpace(commandLine)) return result;

            // 1. Komut satırında gizlenmiş AMSI / ETW Bypass
            foreach (var (pat, score, desc) in AmsiEtwBypassSignatures)
            {
                if (commandLine.Contains(pat, StringComparison.OrdinalIgnoreCase))
                {
                    result.DetectedTechniques |= AntiEvasionTechnique.AmsiEtwPatching;
                    result.TechniqueDescriptions.Add($"Komut Satırı AMSI/ETW Yamalama: {pat}");
                    result.EvasionScore += score;
                    result.Evidences.Add(new SecurityEvidence
                    {
                        Category = EvidenceCategory.AntiEvasion,
                        RuleName = "CLI_AMSI_ETW_TAMPERING",
                        ScoreContribution = score,
                        Confidence = EvidenceConfidence.High,
                        Description = desc
                    });
                }
            }

            // 2. Yüksek zaman gecikmesiyle analiz atlatma (Sleep Evasion)
            if (commandLine.Contains("Start-Sleep", StringComparison.OrdinalIgnoreCase) &&
                (commandLine.Contains("-s 300", StringComparison.OrdinalIgnoreCase) || commandLine.Contains("-s 600", StringComparison.OrdinalIgnoreCase)))
            {
                result.DetectedTechniques |= AntiEvasionTechnique.TimingSleepDelay;
                result.TechniqueDescriptions.Add("Sleep Evasion: Analiz motorunu bekletmek için uzun uyku süresi");
                result.EvasionScore += 20;
                result.Evidences.Add(new SecurityEvidence
                {
                    Category = EvidenceCategory.AntiEvasion,
                    RuleName = "TIMING_SLEEP_EVASION",
                    ScoreContribution = 20,
                    Confidence = EvidenceConfidence.Medium,
                    Description = "Sandbox analiz zaman aşımını tetiklemek için uzun uyku komutu."
                });
            }

            result.EvasionScore = Math.Min(100, result.EvasionScore);
            result.HasEvasionTechniques = result.EvasionScore >= 20 || result.DetectedTechniques != AntiEvasionTechnique.None;

            return result;
        }

        private static bool ContainsIndirectSyscallStub(byte[] bytes)
        {
            if (bytes.Length < 9) return false;

            for (int i = 0; i <= bytes.Length - 7; i++)
            {
                // Check Prefix: 4C 8B D1 B8 (mov r10, rcx; mov eax, [id])
                if (bytes[i] == SyscallPatternPrefix[0] &&
                    bytes[i + 1] == SyscallPatternPrefix[1] &&
                    bytes[i + 2] == SyscallPatternPrefix[2] &&
                    bytes[i + 3] == SyscallPatternPrefix[3])
                {
                    // Check Suffix: 0F 05 C3 (syscall; ret) within 24 bytes
                    for (int j = i + 4; j <= Math.Min(i + 24, bytes.Length - 3); j++)
                    {
                        if (bytes[j] == SyscallPatternSuffix[0] &&
                            bytes[j + 1] == SyscallPatternSuffix[1] &&
                            bytes[j + 2] == SyscallPatternSuffix[2])
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }
    }
}
