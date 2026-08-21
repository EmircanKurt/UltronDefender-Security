using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Contracts.Behavior;
using AegisPC.Core.Models;
using AegisPC.Security.Behavior;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class BehaviorChainTests
    {
        [Fact]
        public void Test_ProcessLineageTracker_BuildsAncestorsAndDescendantsTree()
        {
            var tracker = new ProcessLineageTracker();

            // Tree: explorer.exe (100) -> cmd.exe (200) -> powershell.exe (300) -> vssadmin.exe (400)
            tracker.RegisterProcess(new ProcessNode { Pid = 100, ParentPid = 0, ProcessName = "explorer.exe", ExecutablePath = @"C:\Windows\explorer.exe" });
            tracker.RegisterProcess(new ProcessNode { Pid = 200, ParentPid = 100, ProcessName = "cmd.exe", ExecutablePath = @"C:\Windows\System32\cmd.exe" });
            tracker.RegisterProcess(new ProcessNode { Pid = 300, ParentPid = 200, ProcessName = "powershell.exe", ExecutablePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" });
            tracker.RegisterProcess(new ProcessNode { Pid = 400, ParentPid = 300, ProcessName = "vssadmin.exe", ExecutablePath = @"C:\Windows\System32\vssadmin.exe" });

            // Test Ancestors of PID 400
            var ancestors = tracker.GetAncestors(400);
            Assert.Equal(3, ancestors.Count);
            Assert.Equal(300, ancestors[0].Pid);
            Assert.Equal(200, ancestors[1].Pid);
            Assert.Equal(100, ancestors[2].Pid);

            // Test Descendants of PID 100
            var descendants = tracker.GetDescendants(100);
            Assert.Equal(3, descendants.Count);
            Assert.Contains(descendants, d => d.Pid == 200);
            Assert.Contains(descendants, d => d.Pid == 300);
            Assert.Contains(descendants, d => d.Pid == 400);
        }

        [Fact]
        public void Test_ProcessLineageTracker_DetectsOfficeMacroAndBrowserRceLolbinSpawn()
        {
            var tracker = new ProcessLineageTracker();

            var winword = new ProcessNode { Pid = 101, ProcessName = "WINWORD.EXE", ExecutablePath = @"C:\Program Files\Microsoft Office\WINWORD.EXE" };
            var powershell = new ProcessNode { Pid = 102, ParentPid = 101, ProcessName = "powershell.exe", CommandLine = "powershell -enc AAAA" };
            var chrome = new ProcessNode { Pid = 201, ProcessName = "chrome.exe", ExecutablePath = @"C:\Program Files\Google\Chrome\chrome.exe" };
            var cmd = new ProcessNode { Pid = 202, ParentPid = 201, ProcessName = "cmd.exe", CommandLine = "cmd /c whoami" };

            tracker.RegisterProcess(winword);
            tracker.RegisterProcess(powershell);
            tracker.RegisterProcess(chrome);
            tracker.RegisterProcess(cmd);

            // Office -> PowerShell
            bool isOfficeSuspicious = tracker.IsSuspiciousParentChild(101, 102, out var officeReason);
            Assert.True(isOfficeSuspicious);
            Assert.Contains("Office Makro", officeReason, StringComparison.OrdinalIgnoreCase);

            // Chrome -> Cmd
            bool isBrowserSuspicious = tracker.IsSuspiciousParentChild(201, 202, out var browserReason);
            Assert.True(isBrowserSuspicious);
            Assert.Contains("Tarayıcı RCE", browserReason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Test_ProcessLineageTracker_DetectsFakeSubsystemImpersonation()
        {
            var tracker = new ProcessLineageTracker();

            var explorer = new ProcessNode { Pid = 50, ProcessName = "explorer.exe" };
            var fakeSvchost = new ProcessNode { Pid = 501, ParentPid = 50, ProcessName = "svchost.exe" };
            var fakeLsass = new ProcessNode { Pid = 502, ParentPid = 50, ProcessName = "lsass.exe" };

            tracker.RegisterProcess(explorer);
            tracker.RegisterProcess(fakeSvchost);
            tracker.RegisterProcess(fakeLsass);

            // Fake Svchost (not spawned by services.exe)
            bool isFakeSvchost = tracker.IsSuspiciousParentChild(50, 501, out var svchostReason);
            Assert.True(isFakeSvchost);
            Assert.Contains("Sahte Alt Sistem", svchostReason, StringComparison.OrdinalIgnoreCase);

            // Fake Lsass (not spawned by wininit.exe)
            bool isFakeLsass = tracker.IsSuspiciousParentChild(50, 502, out var lsassReason);
            Assert.True(isFakeLsass);
            Assert.Contains("Sahte LSASS", lsassReason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Test_ProcessInjectionDetector_DetectsProcessHollowingSequence()
        {
            var detector = new ProcessInjectionDetector();
            var apis = new[] { "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext" };

            var eval = detector.EvaluateApiSequence(1100, 2200, apis, "dropper.exe", "svchost.exe");

            Assert.True(eval.IsInjectionDetected);
            Assert.Equal(ProcessInjectionTechnique.ProcessHollowing, eval.Technique);
            Assert.True(eval.SeverityScore >= 90);
            Assert.Contains("Process Hollowing", eval.Explanation);
        }

        [Fact]
        public void Test_ProcessInjectionDetector_DetectsEarlyBirdApcInjection()
        {
            var detector = new ProcessInjectionDetector();
            var apis = new[] { "VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC" };

            var eval = detector.EvaluateApiSequence(1100, 2200, apis, "malware.exe", "notepad.exe");

            Assert.True(eval.IsInjectionDetected);
            Assert.Equal(ProcessInjectionTechnique.EarlyBirdApcInjection, eval.Technique);
            Assert.True(eval.SeverityScore >= 85);
            Assert.Contains("Early Bird APC", eval.Explanation);
        }

        [Fact]
        public void Test_ProcessInjectionDetector_DetectsRemoteThreadInjection()
        {
            var detector = new ProcessInjectionDetector();
            var apis = new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" };

            var eval = detector.EvaluateApiSequence(1100, 2200, apis, "loader.exe", "explorer.exe");

            Assert.True(eval.IsInjectionDetected);
            Assert.Equal(ProcessInjectionTechnique.RemoteThreadInjection, eval.Technique);
            Assert.True(eval.SeverityScore >= 80);
            Assert.Contains("Remote Thread", eval.Explanation);
        }

        [Fact]
        public void Test_AttackChainCorrelator_CorrelatesMultiStageAttackChain()
        {
            var lineageTracker = new ProcessLineageTracker();
            var correlator = new AttackChainCorrelator(lineageTracker);

            int attackPid = 777;
            lineageTracker.RegisterProcess(new ProcessNode
            {
                Pid = attackPid,
                ProcessName = "invoice_macro.exe",
                ExecutablePath = @"C:\Users\PC\Downloads\invoice_macro.exe"
            });

            // Stage 1: Child Spawn
            correlator.RecordEvent(new BehaviorEvent
            {
                ProcessId = attackPid,
                ProcessName = "invoice_macro.exe",
                EventType = BehaviorEventType.ChildProcessSpawn,
                TargetResource = "powershell.exe",
                CommandLine = "-enc KABuAGUAdwA...",
                Timestamp = DateTime.UtcNow.AddSeconds(-20)
            });

            // Stage 2: AMSI Bypass
            correlator.RecordEvent(new BehaviorEvent
            {
                ProcessId = attackPid,
                ProcessName = "invoice_macro.exe",
                EventType = BehaviorEventType.AmsiBypassAttempt,
                Details = "amsiInitFailed memory patch applied",
                Timestamp = DateTime.UtcNow.AddSeconds(-15)
            });

            // Stage 3: ShadowCopy Deletion
            correlator.RecordEvent(new BehaviorEvent
            {
                ProcessId = attackPid,
                ProcessName = "invoice_macro.exe",
                EventType = BehaviorEventType.ShadowCopyDeletion,
                Details = "vssadmin delete shadows /all /quiet",
                Timestamp = DateTime.UtcNow.AddSeconds(-5)
            });

            var chain = correlator.EvaluateChain(attackPid, TimeSpan.FromSeconds(60));

            Assert.True(chain.IsConfirmedAttack);
            Assert.True(chain.TotalRiskScore >= 85);
            Assert.True(chain.MitreTactics.Count >= 3);
            Assert.Contains(chain.MitreTactics, t => t.Contains("Execution"));
            Assert.Contains(chain.MitreTactics, t => t.Contains("Defense Evasion"));
            Assert.Contains(chain.MitreTactics, t => t.Contains("Impact"));
        }

        [Fact]
        public async Task Test_BehaviorEngine_FullLifecycle_ContainmentAndIncidentCreation()
        {
            var engine = new BehaviorEngine();
            SecurityIncident? capturedIncident = null;
            engine.OnIncidentCreated += inc => capturedIncident = inc;

            int rootPid = 9999;

            // Send correlated multi-stage malicious events
            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = rootPid,
                ProcessName = "ransom_dropper.exe",
                EventType = BehaviorEventType.ChildProcessSpawn,
                TargetResource = "powershell.exe",
                CommandLine = "powershell -enc bypass",
                Timestamp = DateTime.UtcNow
            });

            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = rootPid,
                ProcessName = "ransom_dropper.exe",
                EventType = BehaviorEventType.AmsiBypassAttempt,
                TargetResource = "amsi.dll",
                Details = "AmsiScanBuffer patched",
                Timestamp = DateTime.UtcNow
            });

            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = rootPid,
                ProcessName = "ransom_dropper.exe",
                EventType = BehaviorEventType.ShadowCopyDeletion,
                TargetResource = "vssadmin.exe",
                Details = "vssadmin delete shadows /all /quiet",
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(capturedIncident);
            Assert.Equal(rootPid, capturedIncident.RootPid);
            Assert.Equal("Contained", capturedIncident.Status);
            Assert.True(capturedIncident.RiskScore >= 75);
            Assert.NotEmpty(capturedIncident.Evidences);
            Assert.NotEmpty(capturedIncident.Timeline);
            Assert.NotEmpty(capturedIncident.HumanExplanation);
        }
    }
}
