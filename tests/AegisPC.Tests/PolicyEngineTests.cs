using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.App.Views;
using AegisPC.Contracts.Policy;
using AegisPC.Contracts.Safety;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Policy;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class PolicyEngineTests : IDisposable
    {
        private readonly string _testSandboxDir;
        private readonly string _vaultDir;
        private readonly IHashService _hashService;
        private readonly IQuarantineService _quarantineService;
        private readonly ISecurityFindingService _findingService;
        private readonly TestSettingsService _settingsService;
        private readonly FakeToastService _toastService;
        private readonly FakeAuditLogService _auditLogService;
        private readonly IProtectedPathGuard _protectedPathGuard;
        private readonly IReparsePointGuard _reparsePointGuard;

        public PolicyEngineTests()
        {
            _testSandboxDir = Path.Combine(Path.GetTempPath(), "PolicyEngineTests_" + Guid.NewGuid().ToString("N"));
            _vaultDir = Path.Combine(_testSandboxDir, "Vault");
            Directory.CreateDirectory(_testSandboxDir);
            Directory.CreateDirectory(_vaultDir);

            _hashService = new HashService();
            _findingService = new SecurityFindingService();
            _settingsService = new TestSettingsService();
            _toastService = new FakeToastService();
            _auditLogService = new FakeAuditLogService();
            _protectedPathGuard = new ProtectedPathGuard();
            _reparsePointGuard = new ReparsePointGuard();
            _quarantineService = new QuarantineService(_hashService, null, null, _vaultDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandboxDir))
                {
                    Directory.Delete(_testSandboxDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task PolicyEngine_ConfirmedMalware_AutoQuarantined_And_Resolved()
        {
            // Arrange
            var testFile = Path.Combine(_testSandboxDir, "confirmed_threat_sample.bin");
            await File.WriteAllTextAsync(testFile, "MOCK_THREAT_PAYLOAD_BINARY_DATA_NON_BENIGN_TEST");

            var engine = new PolicyEngine(
                settingsService: _settingsService,
                quarantineService: _quarantineService,
                findingService: _findingService,
                protectedPathGuard: _protectedPathGuard,
                reparsePointGuard: _reparsePointGuard,
                toastService: _toastService,
                auditLogService: _auditLogService);

            var finding = new SecurityFinding
            {
                ObjectPath = testFile,
                ObjectName = Path.GetFileName(testFile),
                Title = "EICAR-Test-Signature",
                RiskScore = 95,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Category = FindingCategory.KnownMalwareHash,
                Status = FindingStatus.Active
            };

            // Act
            var eval = engine.EvaluateFinding(finding);
            Assert.Equal(PolicyDecisionAction.AutoQuarantine, eval.Action);

            var result = await engine.EnforcePolicyAsync(finding, CancellationToken.None);

            // Assert
            Assert.Equal(PolicyDecisionAction.AutoQuarantine, result.Action);
            Assert.True(result.QuarantinedSuccessfully);
            Assert.False(File.Exists(testFile)); // File moved to quarantine vault
            Assert.Equal(FindingStatus.Resolved, finding.Status);

            // Toast notified with danger type
            Assert.Contains(_toastService.SentToasts, t => t.Type == "Danger" && t.Title.Contains("Karantinaya Alındı"));

            // Audit log recorded
            Assert.Contains(_auditLogService.Entries, e => e.Action == AuditAction.FileQuarantined);
        }

        [Fact]
        public async Task PolicyEngine_MediumThreat_WarnedOnly_FileRemainsUntouched()
        {
            // Arrange
            var testFile = Path.Combine(_testSandboxDir, "suspicious_script.ps1");
            await File.WriteAllTextAsync(testFile, "Write-Output 'Testing suspicious activity'");

            var engine = new PolicyEngine(
                settingsService: _settingsService,
                quarantineService: _quarantineService,
                findingService: _findingService,
                protectedPathGuard: _protectedPathGuard,
                reparsePointGuard: _reparsePointGuard,
                toastService: _toastService,
                auditLogService: _auditLogService);

            var finding = new SecurityFinding
            {
                ObjectPath = testFile,
                ObjectName = Path.GetFileName(testFile),
                Title = "Suspicious-Script-Heuristic",
                RiskScore = 72,
                RiskLevel = RiskLevel.HighRisk,
                Category = FindingCategory.SuspiciousScript,
                Status = FindingStatus.Active
            };

            // Act
            var eval = engine.EvaluateFinding(finding);
            Assert.Equal(PolicyDecisionAction.Warn, eval.Action);

            var result = await engine.EnforcePolicyAsync(finding, CancellationToken.None);

            // Assert
            Assert.Equal(PolicyDecisionAction.Warn, result.Action);
            Assert.False(result.QuarantinedSuccessfully);
            Assert.True(File.Exists(testFile)); // File MUST NOT be deleted or quarantined
            Assert.Equal(FindingStatus.Active, finding.Status);

            // Toast notified with Warning type (B5 routes to Incident Center)
            Assert.Contains(_toastService.SentToasts, t => t.Type == "Warning" && t.Title.Contains("Şüpheli"));

            // Audit log recorded
            Assert.Contains(_auditLogService.Entries, e => e.Action == AuditAction.ScanCompleted);
        }

        [Fact]
        public async Task PolicyEngine_SafetyGuard_MicrosoftSignedFile_NeverAutoQuarantined()
        {
            // Arrange
            var testFile = Path.Combine(_testSandboxDir, "legit_system_tool.exe");
            await File.WriteAllTextAsync(testFile, "MOCK_BINARY_DATA");

            var fakeSignatureVerifier = new FakeSignatureVerifier(new SignatureInfo
            {
                IsSigned = true,
                IsValid = true,
                Publisher = "Microsoft Corporation",
                Issuer = "Microsoft Root Certificate Authority 2010"
            });

            var engine = new PolicyEngine(
                settingsService: _settingsService,
                quarantineService: _quarantineService,
                findingService: _findingService,
                protectedPathGuard: _protectedPathGuard,
                reparsePointGuard: _reparsePointGuard,
                signatureVerifier: fakeSignatureVerifier,
                toastService: _toastService,
                auditLogService: _auditLogService);

            var finding = new SecurityFinding
            {
                ObjectPath = testFile,
                ObjectName = Path.GetFileName(testFile),
                Title = "False-Positive-Threat",
                RiskScore = 95,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Category = FindingCategory.KnownMalwareHash,
                Status = FindingStatus.Active
            };

            // Act
            var eval = await engine.EvaluateFindingAsync(finding, testFile, CancellationToken.None);

            // Assert
            Assert.Equal(PolicyDecisionAction.Warn, eval.Action);
            Assert.True(eval.IsMicrosoftSigned);
            Assert.True(eval.IsProtectedBySafetyGuard);

            var result = await engine.EnforcePolicyAsync(finding, CancellationToken.None);
            Assert.Equal(PolicyDecisionAction.Warn, result.Action);
            Assert.True(File.Exists(testFile)); // File MUST NOT be deleted
        }

        [Fact]
        public void PolicyEngine_SafetyGuard_ProtectedSystemPath_NeverAutoQuarantined()
        {
            // Arrange: Simulated System32 path
            var systemPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "mockdriver.sys");

            var engine = new PolicyEngine(
                settingsService: _settingsService,
                quarantineService: _quarantineService,
                findingService: _findingService,
                protectedPathGuard: _protectedPathGuard,
                reparsePointGuard: _reparsePointGuard,
                toastService: _toastService,
                auditLogService: _auditLogService);

            var finding = new SecurityFinding
            {
                ObjectPath = systemPath,
                ObjectName = "mockdriver.sys",
                Title = "Driver-Suspicion",
                RiskScore = 98,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Category = FindingCategory.KnownMalwareHash,
                Status = FindingStatus.Active
            };

            // Act
            var eval = engine.EvaluateFinding(finding);

            // Assert
            Assert.Equal(PolicyDecisionAction.Warn, eval.Action);
            Assert.True(eval.IsProtectedBySafetyGuard);
        }

        [Fact]
        public void PolicyEngine_AutoQuarantineDisabled_DowngradesToWarn()
        {
            // Arrange
            _settingsService.SetSetting("EnableAutoQuarantine", false);

            var engine = new PolicyEngine(
                settingsService: _settingsService,
                quarantineService: _quarantineService,
                findingService: _findingService,
                protectedPathGuard: _protectedPathGuard,
                reparsePointGuard: _reparsePointGuard);

            var finding = new SecurityFinding
            {
                ObjectPath = @"C:\Users\PC\Downloads\malware.exe",
                ObjectName = "malware.exe",
                Title = "Trojan.Generic",
                RiskScore = 90,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Category = FindingCategory.KnownMalwareHash,
                Status = FindingStatus.Active
            };

            // Act
            var eval = engine.EvaluateFinding(finding);

            // Assert: Disabled auto quarantine means it must downgrade to Warn
            Assert.Equal(PolicyDecisionAction.Warn, eval.Action);
            Assert.Contains("devre dışı", eval.Reason);
        }

        [Fact]
        public void PolicyEngine_CustomThreshold_EnforcesThresholdCorrectly()
        {
            // Arrange: Set threshold to 90
            _settingsService.SetSetting("AutoQuarantineThreshold", 90);

            var engine = new PolicyEngine(
                settingsService: _settingsService,
                quarantineService: _quarantineService,
                findingService: _findingService,
                protectedPathGuard: _protectedPathGuard,
                reparsePointGuard: _reparsePointGuard);

            var finding85 = new SecurityFinding
            {
                ObjectPath = @"C:\Users\PC\Downloads\suspicious.exe",
                ObjectName = "suspicious.exe",
                Title = "Trojan.Heur",
                RiskScore = 85,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Category = FindingCategory.KnownMalwareHash
            };

            var finding92 = new SecurityFinding
            {
                ObjectPath = @"C:\Users\PC\Downloads\confirmed.exe",
                ObjectName = "confirmed.exe",
                Title = "Ransom.Locky",
                RiskScore = 92,
                RiskLevel = RiskLevel.ConfirmedMalicious,
                Category = FindingCategory.KnownMalwareHash
            };

            // Act & Assert
            var eval85 = engine.EvaluateFinding(finding85);
            var eval92 = engine.EvaluateFinding(finding92);

            Assert.Equal(PolicyDecisionAction.Warn, eval85.Action); // Below 90 threshold -> Warn
            Assert.Equal(PolicyDecisionAction.AutoQuarantine, eval92.Action); // Above 90 threshold -> AutoQuarantine
        }

        [Fact]
        public void BugB5_ResolveTargetPage_WarningRoutesToIncidentCenter_ThreatRoutesToQuarantine()
        {
            // Reflection test on ToastNotificationWindow.ResolveTargetPage to guarantee Bug B5 resolution
            var method = typeof(ToastNotificationWindow).GetMethod(
                "ResolveTargetPage",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);

            // 1. Warning toast for suspicious file -> Must route to IncidentCenterView
            var targetWarning = method.Invoke(null, new object?[] { "⚠️ Şüpheli Dosya Uyarısı", "Dosya şüpheli bulundu.", "Warning" }) as Type;
            Assert.Equal(typeof(IncidentCenterView), targetWarning);

            // 2. Uyarıldı toast -> Must route to IncidentCenterView
            var targetUyarildi = method.Invoke(null, new object?[] { "Ultron Defender", "Dosya uyarıldı, olay merkezine kaydedildi.", "Warning" }) as Type;
            Assert.Equal(typeof(IncidentCenterView), targetUyarildi);

            // 3. Danger toast for Quarantined threat -> Must route to QuarantineView
            var targetQuarantine = method.Invoke(null, new object?[] { "🛡️ Tehdit Engellendi ve Karantinaya Alındı", "Zararlı dosya AES-256 kasaya kilitlendi.", "Danger" }) as Type;
            Assert.Equal(typeof(QuarantineView), targetQuarantine);
        }
    }

    internal class TestSettingsService : ISettingsService
    {
        private readonly Dictionary<string, object> _settings = new();

        public AegisPC.Infrastructure.Configuration.AppSettings Current { get; } = new();

        public T GetSetting<T>(string key, T defaultValue)
        {
            if (_settings.TryGetValue(key, out var val) && val is T typedVal)
            {
                return typedVal;
            }
            return defaultValue;
        }

        public void SetSetting<T>(string key, T value)
        {
            if (value != null)
            {
                _settings[key] = value;
            }
        }

        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    internal class FakeToastService : IWindowsToastNotificationService
    {
        public List<(string Title, string Message, string Type)> SentToasts { get; } = new();

        public void ShowToast(string title, string message, string type = "Info")
        {
            SentToasts.Add((title, message, type));
        }
    }

    internal class FakeAuditLogService : IAuditLogService
    {
        public List<AuditLogEntry> Entries { get; } = new();

        public Task LogActionAsync(
            AuditAction action,
            string targetType,
            string targetName,
            string? targetPath = null,
            string? details = null,
            AuditResult result = AuditResult.Success,
            string? errorMessage = null,
            CancellationToken cancellationToken = default)
        {
            Entries.Add(new AuditLogEntry
            {
                Action = action,
                TargetType = targetType,
                TargetName = targetName,
                TargetPath = targetPath,
                Details = details,
                Result = result
            });
            return Task.CompletedTask;
        }

        public Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null, CancellationToken cancellationToken = default)
            => Task.FromResult(Entries);

        public Task ClearLogsAsync(CancellationToken cancellationToken = default)
        {
            Entries.Clear();
            return Task.CompletedTask;
        }
    }

    internal class FakeSignatureVerifier : ISignatureVerifier
    {
        private readonly SignatureInfo _info;

        public FakeSignatureVerifier(SignatureInfo info)
        {
            _info = info;
        }

        public Task<SignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_info);
        }
    }
}
