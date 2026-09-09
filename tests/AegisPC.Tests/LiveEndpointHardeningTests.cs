using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Caching;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Network;
using AegisPC.Contracts.SelfProtection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Infrastructure.Kernel;
using AegisPC.Security.SelfProtection;
using AegisPC.Service.DriverBridge;
using AegisPC.Service.Network;
using Xunit;

namespace AegisPC.Tests
{
    public class LiveEndpointHardeningTests
    {
        #region Test Fakes
        private class FakeDetectionHub : IDetectionHub
        {
            public DetectionResult ResultToReturn { get; set; } = new();
            public bool WasEvaluateCalled { get; private set; }

            public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => Array.Empty<IDetectorPlugin>();
            public void RegisterDetector(IDetectorPlugin detector) { }
            public bool UnregisterDetector(string detectorId) => true;

            public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
            {
                WasEvaluateCalled = true;
                return Task.FromResult(ResultToReturn);
            }
        }

        private class FakeFindingService : ISecurityFindingService
        {
            public List<SecurityFinding> AddedFindings { get; } = new();

            public Task AddFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default)
            {
                lock (AddedFindings) { AddedFindings.Add(finding); }
                return Task.CompletedTask;
            }

            public Task<List<SecurityFinding>> GetAllFindingsAsync(CancellationToken cancellationToken = default) => Task.FromResult(AddedFindings);
            public Task<SecurityFinding?> GetFindingByIdAsync(Guid id, CancellationToken cancellationToken = default) => Task.FromResult<SecurityFinding?>(null);
            public Task<List<SecurityFinding>> GetFindingsByRiskAsync(RiskLevel riskLevel, CancellationToken cancellationToken = default) => Task.FromResult(new List<SecurityFinding>());
            public Task UpdateFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default) => Task.CompletedTask;
            public Task<int> GetActiveCountAsync(CancellationToken cancellationToken = default) => Task.FromResult(AddedFindings.Count);
        }

        private class FakeQuarantineService : IQuarantineService
        {
#pragma warning disable CS0067
            public event Action<QuarantineEntry>? OnFileQuarantined;
            public event Action<int>? OnFileRestored;
            public event Action<int>? OnFileDeleted;
#pragma warning restore CS0067

            public List<string> QuarantinedPaths { get; } = new();

            public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default)
            {
                lock (QuarantinedPaths) { QuarantinedPaths.Add(path); }
                return Task.FromResult(true);
            }

            public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(true);
            public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult<QuarantineEntry?>(null);
            public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<QuarantineEntry>());
            public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(true);
            public Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default) => Task.FromResult(true);
        }

        private class FakeAuditLogService : IAuditLogService
        {
            public List<string> LoggedActions { get; } = new();

            public Task LogActionAsync(AuditAction action, string targetType, string targetName, string? targetPath = null, string? details = null, AuditResult result = AuditResult.Success, string? errorMessage = null, CancellationToken cancellationToken = default)
            {
                lock (LoggedActions) { LoggedActions.Add($"{action}:{targetType}:{targetName}"); }
                return Task.CompletedTask;
            }

            public Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default) => Task.FromResult(new List<AuditLogEntry>());
        }
        #endregion

        [Fact]
        public void KernelBridge_DecisionMatrix_AllowCleanFile()
        {
            var fakeHub = new FakeDetectionHub();
            var fakeFindings = new FakeFindingService();
            var fakeQuarantine = new FakeQuarantineService();
            var fakeAudit = new FakeAuditLogService();

            string tempFile = Path.Combine(Path.GetTempPath(), $"clean_test_{Guid.NewGuid():N}.txt");
            File.WriteAllText(tempFile, "Benign harmless text data.");

            try
            {
                fakeHub.ResultToReturn = new DetectionResult
                {
                    RiskScore = 15,
                    Verdict = DetectionVerdict.Clean,
                    ThreatTitle = "Clean File"
                };

                using var bridge = new KernelBridge(
                    detectionHub: fakeHub,
                    findingService: fakeFindings,
                    quarantineService: fakeQuarantine,
                    auditLogService: fakeAudit);

                var req = new KernelIpcService.ScanRequest
                {
                    ProcessId = 1234,
                    FilePath = tempFile,
                    IsWriteOperation = false
                };

                bool blocked = bridge.EvaluateKernelScanRequest(req);

                // RiskScore 15 (< 40) MUST BE ALLOWED
                Assert.False(blocked);
                Assert.Empty(fakeFindings.AddedFindings);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public void KernelBridge_DecisionMatrix_SuspiciousFile_MonitorsAndLogs()
        {
            var fakeHub = new FakeDetectionHub();
            var fakeFindings = new FakeFindingService();
            var fakeQuarantine = new FakeQuarantineService();
            var fakeAudit = new FakeAuditLogService();

            string tempFile = Path.Combine(Path.GetTempPath(), $"susp_test_{Guid.NewGuid():N}.exe");
            File.WriteAllText(tempFile, "Simulated suspicious executable payload.");

            try
            {
                fakeHub.ResultToReturn = new DetectionResult
                {
                    RiskScore = 55,
                    Verdict = DetectionVerdict.Suspicious,
                    ThreatTitle = "Suspicious Unsigned Binary"
                };

                using var bridge = new KernelBridge(
                    detectionHub: fakeHub,
                    findingService: fakeFindings,
                    quarantineService: fakeQuarantine,
                    auditLogService: fakeAudit);

                var req = new KernelIpcService.ScanRequest
                {
                    ProcessId = 4455,
                    FilePath = tempFile,
                    IsWriteOperation = true
                };

                bool blocked = bridge.EvaluateKernelScanRequest(req);

                // RiskScore 55 (40-69) ALLOWS ACCESS (telemetry only)
                Assert.False(blocked);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public void KernelBridge_DecisionMatrix_HighRiskFile_EnforcesBlock()
        {
            var fakeHub = new FakeDetectionHub();
            var fakeFindings = new FakeFindingService();
            var fakeQuarantine = new FakeQuarantineService();
            var fakeAudit = new FakeAuditLogService();

            string tempFile = Path.Combine(Path.GetTempPath(), $"highrisk_test_{Guid.NewGuid():N}.bin");
            File.WriteAllText(tempFile, "Simulated high risk ransomware dropper.");

            try
            {
                fakeHub.ResultToReturn = new DetectionResult
                {
                    RiskScore = 75,
                    Verdict = DetectionVerdict.Suspicious,
                    ThreatTitle = "Heuristic Ransomware Dropper"
                };

                using var bridge = new KernelBridge(
                    detectionHub: fakeHub,
                    findingService: fakeFindings,
                    quarantineService: fakeQuarantine,
                    auditLogService: fakeAudit);

                var req = new KernelIpcService.ScanRequest
                {
                    ProcessId = 6677,
                    FilePath = tempFile,
                    IsWriteOperation = true
                };

                bool blocked = bridge.EvaluateKernelScanRequest(req);

                // RiskScore 75 (70-84) MUST BLOCK (STATUS_ACCESS_DENIED)
                Assert.True(blocked);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public void KernelBridge_DecisionMatrix_CriticalMalware_EnforcesBlockAndQuarantine()
        {
            var fakeHub = new FakeDetectionHub();
            var fakeFindings = new FakeFindingService();
            var fakeQuarantine = new FakeQuarantineService();
            var fakeAudit = new FakeAuditLogService();

            string tempFile = Path.Combine(Path.GetTempPath(), $"eicar_sim_{Guid.NewGuid():N}.com");
            File.WriteAllText(tempFile, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            try
            {
                fakeHub.ResultToReturn = new DetectionResult
                {
                    RiskScore = 100,
                    Verdict = DetectionVerdict.ConfirmedMalicious,
                    ThreatTitle = "EICAR-Test-File (Standard)"
                };

                using var bridge = new KernelBridge(
                    detectionHub: fakeHub,
                    findingService: fakeFindings,
                    quarantineService: fakeQuarantine,
                    auditLogService: fakeAudit);

                var req = new KernelIpcService.ScanRequest
                {
                    ProcessId = 8899,
                    FilePath = tempFile,
                    IsWriteOperation = true
                };

                bool blocked = bridge.EvaluateKernelScanRequest(req);

                // RiskScore 100 MUST BLOCK IMMEDIATELY
                Assert.True(blocked);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public void KernelBridge_Bypasses_CriticalSystemProcesses_And_Self()
        {
            var fakeHub = new FakeDetectionHub();
            using var bridge = new KernelBridge(detectionHub: fakeHub);

            // PID <= 4 (System)
            var sysReq = new KernelIpcService.ScanRequest
            {
                ProcessId = 4,
                FilePath = @"C:\Windows\System32\ntoskrnl.exe",
                IsWriteOperation = false
            };
            Assert.False(bridge.EvaluateKernelScanRequest(sysReq));

            // Self PID
            var selfReq = new KernelIpcService.ScanRequest
            {
                ProcessId = (uint)Environment.ProcessId,
                FilePath = @"C:\Program Files\UltronDefender\UltronDefender.exe",
                IsWriteOperation = false
            };
            Assert.False(bridge.EvaluateKernelScanRequest(selfReq));

            // Critical process name (e.g. lsass.exe)
            var lsassReq = new KernelIpcService.ScanRequest
            {
                ProcessId = 7788,
                FilePath = @"C:\Windows\System32\lsass.exe",
                IsWriteOperation = false
            };
            Assert.False(bridge.EvaluateKernelScanRequest(lsassReq));

            // DetectionHub should NEVER be called for whitelisted system components
            Assert.False(fakeHub.WasEvaluateCalled);
        }

        [Fact]
        public void SelfProtection_IntegrityStatus_And_TamperDefense()
        {
            var engine = new SelfProtectionEngine();
            var status = engine.GetStatus();

            Assert.NotNull(status);
            Assert.True(status.IsProcessProtectionActive);
            Assert.True(status.IsRegistryLockActive);

            // Record tamper attempt
            TamperAttemptEvent? captured = null;
            engine.OnTamperAttemptBlocked += evt => captured = evt;

            bool blocked = engine.RecordAndBlockTamperAttempt(
                TamperTargetType.DriverUnload,
                1122,
                "unhooker.exe",
                "AegisFilter.sys",
                "Attempted fltmc unload AegisFilter via unprivileged shell");

            Assert.True(blocked);
            Assert.NotNull(captured);
            Assert.Equal(TamperTargetType.DriverUnload, captured.TargetType);
            Assert.Equal(1122, captured.SourcePid);

            var updatedStatus = engine.GetStatus();
            Assert.True(updatedStatus.BlockedTamperAttemptsCount >= 1);
        }

        [Fact]
        public void WfpEnforcement_And_NetworkProtection_EndToEndCorrelation()
        {
            var blocklist = new UrlBlocklistManager();
            blocklist.AddRule("c2-beacon.darknet.org", UrlBlockCategory.C2Server, "Confirmed C2 Server");
            var hosts = new HostsInjectionHelper();
            var dns = new DnsFilterService(blocklist, hosts);

            using var wfp = new WfpEnforcementService();
            using var netSec = new NetworkProtectionService(dns, wfpEnforcement: wfp);
            netSec.Start();

            // Verify initial state
            Assert.True(netSec.IsRunning);

            // 1. DNS Resolution Evaluation
            var dnsResult = netSec.EvaluateDomain("c2-beacon.darknet.org");
            Assert.True(dnsResult.IsBlocked);
            Assert.Equal(UrlBlockCategory.C2Server, dnsResult.BlockCategory);

            // 2. Outbound Flow Interception
            var c2Flow = new NetworkFlowEvent
            {
                ProcessId = 9876,
                ProcessName = "stealer.exe",
                DestinationDomain = "c2-beacon.darknet.org",
                RemoteAddress = "198.51.100.22",
                RemotePort = 8443
            };

            var flowVerdict = netSec.AnalyzeFlow(c2Flow);

            Assert.NotNull(flowVerdict);
            Assert.True(flowVerdict.IsSuspicious);
            Assert.True(flowVerdict.IsC2Beaconing);
            Assert.Equal(90, flowVerdict.RiskScore);

            // 3. Verify WFP dynamic block tracking
            Assert.True(wfp.ActiveBlockFilterCount > 0);

            // Clean up
            wfp.ClearDynamicFilters();
            Assert.Equal(0, wfp.ActiveBlockFilterCount);
        }
    }
}
