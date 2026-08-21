using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Security.RealTime;
using Xunit;

namespace AegisPC.Tests
{
    public class BehaviorAnalyzerTests
    {
        [Fact]
        public async Task MultiStageAttackChain_EscalatesToCriticalAndCreatesIncident()
        {
            var engine = new BehaviorEngine();
            SecurityIncident? createdIncident = null;
            engine.OnIncidentCreated += (inc) => createdIncident = inc;

            int pid = 9988;
            string rootPath = @"C:\Users\Test\Downloads\crack_keygen.exe";

            // Event 1: Child process with encoded PowerShell
            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = pid,
                ProcessName = "crack_keygen.exe",
                ExecutablePath = rootPath,
                EventType = BehaviorEventType.ChildProcessSpawn,
                TargetResource = "powershell.exe",
                CommandLine = "-enc JABhID0A... -ExecutionPolicy Bypass"
            });

            // Event 2: Persistence in Run Key
            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = pid,
                ProcessName = "crack_keygen.exe",
                ExecutablePath = rootPath,
                EventType = BehaviorEventType.RegistryPersistence,
                TargetResource = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KeygenUpdater"
            });

            // Event 3: Chrome Browser Data Access
            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = pid,
                ProcessName = "crack_keygen.exe",
                ExecutablePath = rootPath,
                EventType = BehaviorEventType.BrowserDataAccess,
                TargetResource = @"C:\Users\Test\AppData\Local\Google\Chrome\User Data\Default\Login Data"
            });

            // Assertions
            Assert.NotNull(createdIncident);
            Assert.Equal("CRITICAL", createdIncident.RiskLevel);
            Assert.True(createdIncident.RiskScore >= 75);
            Assert.Contains("Login Data", createdIncident.HumanExplanation);
            Assert.NotEmpty(createdIncident.Evidences);
            Assert.NotEmpty(createdIncident.Timeline);
        }

        [Fact]
        public async Task BenignProcess_DoesNotEscalateToCritical()
        {
            var engine = new BehaviorEngine();
            SecurityIncident? createdIncident = null;
            engine.OnIncidentCreated += (inc) => createdIncident = inc;

            int pid = 4455;
            // Normal process opening a document
            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = pid,
                ProcessName = "notepad.exe",
                ExecutablePath = @"C:\Windows\System32\notepad.exe",
                EventType = BehaviorEventType.ProcessSpawn,
                TargetResource = @"C:\Users\Test\Documents\notes.txt"
            });

            var incidents = await engine.GetActiveIncidentsAsync();
            Assert.Null(createdIncident);
            Assert.Empty(incidents);
        }

        [Fact]
        public async Task RansomwareBehavior_TriggersRansomwareIncident()
        {
            var engine = new BehaviorEngine();
            SecurityIncident? createdIncident = null;
            engine.OnIncidentCreated += (inc) => createdIncident = inc;

            int pid = 7711;
            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = pid,
                ProcessName = "locker.exe",
                ExecutablePath = @"C:\Users\Test\AppData\Local\Temp\locker.exe",
                EventType = BehaviorEventType.ShadowCopyDeletion,
                TargetResource = "vssadmin.exe delete shadows /all /quiet",
                Details = "Gölge kopyaları silme eylemi tespit edildi."
            });

            await engine.ProcessEventAsync(new BehaviorEvent
            {
                ProcessId = pid,
                ProcessName = "locker.exe",
                ExecutablePath = @"C:\Users\Test\AppData\Local\Temp\locker.exe",
                EventType = BehaviorEventType.FileEncryptionAttempt,
                TargetResource = @"C:\Users\Test\Documents\report.docx.locked",
                Details = "Toplu dosya şifreleme ve uzantı değiştirme"
            });

            Assert.NotNull(createdIncident);
            Assert.Equal("CRITICAL", createdIncident.RiskLevel);
            Assert.Contains("Ransom", createdIncident.ThreatName);
        }
    }
}
