using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class QuarantinePolicyAutoEnforcementTests : IDisposable
    {
        private readonly string _testSandbox;
        private readonly string _vaultDir;
        private readonly QuarantineService _quarantineService;
        private readonly SecurityFindingService _findingService;
        private readonly TestAuditLogService _auditLogService;

        public QuarantinePolicyAutoEnforcementTests()
        {
            _testSandbox = Path.Combine(Path.GetTempPath(), "Aegis_AutoQuarTest_" + Guid.NewGuid().ToString("N")[..8]);
            _vaultDir = Path.Combine(_testSandbox, "Vault");
            Directory.CreateDirectory(_testSandbox);
            Directory.CreateDirectory(_vaultDir);

            _auditLogService = new TestAuditLogService();
            _quarantineService = new QuarantineService(
                hashService: new HashService(),
                auditLogService: _auditLogService,
                customVaultDir: _vaultDir);
            _findingService = new SecurityFindingService();
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testSandbox))
                {
                    Directory.Delete(_testSandbox, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task AutoQuarantine_EicarHighRiskThreat_QuarantinesFileUpdatesFindingAndLogsAudit()
        {
            // 1. Create a simulated malware test file
            var threatFilePath = Path.Combine(_testSandbox, "eicar_auto_malware.exe");
            await File.WriteAllTextAsync(threatFilePath, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            // 2. Setup mock/stub scanner that identifies this file with RiskScore = 95
            var stubScanner = new StubFileScanner(new List<SecurityFinding>
            {
                new SecurityFinding
                {
                    Id = Guid.NewGuid(),
                    ObjectName = "eicar_auto_malware.exe",
                    ObjectPath = threatFilePath,
                    Title = "🚨 Zararlı Yazılım / EICAR: eicar_auto_malware.exe",
                    RiskScore = 95,
                    RiskLevel = RiskLevel.ConfirmedMalicious,
                    Status = FindingStatus.Active,
                    Category = FindingCategory.KnownMalwareHash
                }
            });

            var coordinator = new ScanCoordinatorService(
                stubScanner,
                _findingService,
                _quarantineService,
                _auditLogService);

            // 3. Execute Scan
            var result = await coordinator.StartScanAsync(ScanType.Custom, _testSandbox);

            // 4. Verification
            Assert.NotNull(result);
            Assert.Single(result.Findings);
            var finding = result.Findings[0];

            // Finding status must be marked as Resolved because it was auto-quarantined
            Assert.Equal(FindingStatus.Resolved, finding.Status);

            // Source malware file must be removed from disk
            Assert.False(File.Exists(threatFilePath), "Original malware file must be removed by auto-quarantine.");

            // Quarantine vault must contain the file
            var quarantinedItems = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.Single(quarantinedItems);
            Assert.Equal(threatFilePath, quarantinedItems[0].OriginalPath);

            // Audit log must record the FileQuarantined action
            var auditLogs = await _auditLogService.GetLogsAsync();
            Assert.Contains(auditLogs, a => a.Action == AuditAction.FileQuarantined && a.TargetPath == threatFilePath);
        }

        [Fact]
        public async Task AutoQuarantine_SuspiciousRiskScore75_WarnsWithoutDeletingFile()
        {
            // 1. Create a suspicious script file
            var suspiciousFilePath = Path.Combine(_testSandbox, "suspicious_script.ps1");
            await File.WriteAllTextAsync(suspiciousFilePath, "Get-Process | Where-Object { $_.CPU -gt 10 }");

            // 2. Setup mock scanner with RiskScore = 75 (between 60 and 84: Uyarıldı)
            var stubScanner = new StubFileScanner(new List<SecurityFinding>
            {
                new SecurityFinding
                {
                    Id = Guid.NewGuid(),
                    ObjectName = "suspicious_script.ps1",
                    ObjectPath = suspiciousFilePath,
                    Title = "⚠️ Şüpheli Powershell Betiği",
                    RiskScore = 75,
                    RiskLevel = RiskLevel.HighRisk,
                    Status = FindingStatus.Active,
                    Category = FindingCategory.SuspiciousScript
                }
            });

            var coordinator = new ScanCoordinatorService(
                stubScanner,
                _findingService,
                _quarantineService,
                _auditLogService);

            // 3. Execute Scan
            var result = await coordinator.StartScanAsync(ScanType.Custom, _testSandbox);

            // 4. Verification
            Assert.NotNull(result);
            Assert.Single(result.Findings);
            var finding = result.Findings[0];

            // Finding status remains Active (not resolved/quarantined)
            Assert.Equal(FindingStatus.Active, finding.Status);

            // Source file must STILL exist (no accidental deletion)
            Assert.True(File.Exists(suspiciousFilePath), "Suspicious file (60-84) must NOT be deleted automatically.");

            // Quarantine vault must be empty
            var quarantinedItems = await _quarantineService.GetQuarantinedItemsAsync();
            Assert.Empty(quarantinedItems);

            // Audit log should record the warning/scan completed event
            var auditLogs = await _auditLogService.GetLogsAsync();
            Assert.Contains(auditLogs, a => a.TargetPath == suspiciousFilePath && a.Details != null && a.Details.Contains("uyarıldı"));
        }

        private sealed class StubFileScanner : IFileScanner
        {
            private readonly List<SecurityFinding> _stubFindings;

            public StubFileScanner(List<SecurityFinding> stubFindings)
            {
                _stubFindings = stubFindings;
            }

            public bool IsPaused => false;

            public Task<ScanResult> ScanDirectoryAsync(
                string path,
                ScanType scanType,
                IProgress<ScanProgress>? progress = null,
                CancellationToken cancellationToken = default)
            {
                var result = new ScanResult
                {
                    ScanType = scanType,
                    CustomPath = path,
                    ScannedFiles = 1,
                    TotalFiles = 1,
                    Findings = _stubFindings,
                    ElapsedMs = 50,
                    StartedAt = DateTime.UtcNow,
                    CompletedAt = DateTime.UtcNow,
                    Status = ScanStatus.Completed
                };

                return Task.FromResult(result);
            }

            public Task<SecurityFinding?> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(_stubFindings.FirstOrDefault(f => f.ObjectPath == filePath));
            }

            public Task<FileScanDetailedResult> ScanFileDetailedAsync(string path, TimeSpan perFileTimeout, CancellationToken cancellationToken = default)
            {
                var finding = _stubFindings.FirstOrDefault(f => f.ObjectPath == path);
                return Task.FromResult(FileScanDetailedResult.CreateSuccess(path, finding, TimeSpan.Zero));
            }

            public void PauseScan() { }
            public void ResumeScan() { }
        }

        private sealed class TestAuditLogService : IAuditLogService
        {
            private readonly List<AuditLogEntry> _entries = new();

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
                lock (_entries)
                {
                    _entries.Add(new AuditLogEntry
                    {
                        Action = action,
                        TargetType = targetType,
                        TargetName = targetName,
                        TargetPath = targetPath,
                        Details = details,
                        Result = result,
                        ErrorMessage = errorMessage,
                        Timestamp = DateTime.UtcNow
                    });
                }
                return Task.CompletedTask;
            }

            public Task<List<AuditLogEntry>> GetLogsAsync(
                DateTime? from = null,
                DateTime? to = null,
                CancellationToken cancellationToken = default)
            {
                lock (_entries)
                {
                    return Task.FromResult(_entries.ToList());
                }
            }
        }
    }
}
