using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.App.ViewModels;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class QuarantineUnifiedIntegrationTests : IDisposable
    {
        private readonly string _testRoot;
        private readonly string _vaultDir;
        private readonly QuarantineService _quarantineService;

        public QuarantineUnifiedIntegrationTests()
        {
            _testRoot = Path.Combine(Path.GetTempPath(), "Aegis_QuarUnifiedTest_" + Guid.NewGuid().ToString("N")[..8]);
            _vaultDir = Path.Combine(_testRoot, "Vault");
            Directory.CreateDirectory(_testRoot);
            Directory.CreateDirectory(_vaultDir);

            _quarantineService = new QuarantineService(
                hashService: new HashService(),
                customVaultDir: _vaultDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testRoot))
                {
                    Directory.Delete(_testRoot, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task QuarantineUnified_EicarThreat_AppearsInBothQuarantineAndIncidentTabs()
        {
            // 1. Create a physical test threat file (EICAR simulation)
            var sampleMalwarePath = Path.Combine(_testRoot, "eicar_test_threat.bin");
            await File.WriteAllBytesAsync(sampleMalwarePath, System.Text.Encoding.UTF8.GetBytes("EICAR_TEST_SIMULATION_PAYLOAD_" + Guid.NewGuid().ToString("N")));

            // 2. Quarantine the file via real QuarantineService (AES-256 encrypted vault container)
            bool quarSuccess = await _quarantineService.QuarantineFileAsync(sampleMalwarePath, "EICAR-Standard-AV-Test-File (Pattern Match)");
            Assert.True(quarSuccess, "QuarantineFileAsync must succeed for test malware.");
            Assert.False(File.Exists(sampleMalwarePath), "Original malware file must be removed from its source directory.");

            // 3. Initialize Unified QuarantineViewModel
            var vm = new QuarantineViewModel(quarantineService: _quarantineService);
            await vm.RefreshAllDataAsync();

            // 4. VERIFY TAB 1: Quarantine Vault
            Assert.NotEmpty(vm.QuarantinedItems);
            Assert.False(vm.HasNoQuarantinedItems);
            var quarItem = vm.QuarantinedItems.FirstOrDefault(q => q.FileName == "eicar_test_threat.bin");
            Assert.NotNull(quarItem);
            Assert.Equal(sampleMalwarePath, quarItem.OriginalPath);
            Assert.Contains("EICAR", quarItem.Reason);

            // 5. VERIFY TAB 2: Threat & Incident History (EDR)
            // Bi-directional consistency: Quarantined files must automatically surface in Incidents
            Assert.NotEmpty(vm.Incidents);
            Assert.False(vm.HasNoIncidents);
            var incidentItem = vm.Incidents.FirstOrDefault(i => i.RootProcessName == "eicar_test_threat.bin");
            Assert.NotNull(incidentItem);
            Assert.Equal("Quarantined", incidentItem.Status);
            Assert.Contains("Karantina Kasasına Kilitlendi", incidentItem.ActionTaken);
            Assert.Contains("EICAR", incidentItem.ThreatName);
            Assert.True(incidentItem.RiskScore >= 85, "EICAR risk score must be high or critical.");
            Assert.NotEmpty(incidentItem.Timeline);
        }

        [Fact]
        public async Task QuarantineUnified_RestoreAction_RestoresFileAndKeepsConsistency()
        {
            // 1. Create and quarantine test file
            var filePath = Path.Combine(_testRoot, "suspicious_payload.exe");
            await File.WriteAllBytesAsync(filePath, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 });

            await _quarantineService.QuarantineFileAsync(filePath, "Heuristic.SuspiciousPeHeader");

            var vm = new QuarantineViewModel(quarantineService: _quarantineService);
            await vm.RefreshAllDataAsync();

            Assert.Single(vm.QuarantinedItems);
            var entry = vm.QuarantinedItems.First();

            // 2. Perform Restore action
            await vm.RestoreItemAsync(entry);

            // 3. Physical verification: file is back in source folder
            Assert.True(File.Exists(filePath), "Restored file must physically exist back on disk.");
            Assert.Empty(vm.QuarantinedItems);
            Assert.True(vm.HasNoQuarantinedItems);
        }

        [Fact]
        public void QuarantineUnified_TabSwitching_TogglesActiveState()
        {
            var vm = new QuarantineViewModel();

            // Default state: Quarantine tab active
            Assert.True(vm.IsQuarantineTabActive);
            Assert.False(vm.IsIncidentsTabActive);

            // Switch to Incidents tab via command
            vm.SelectIncidentsTabCommand.Execute(null);
            Assert.False(vm.IsQuarantineTabActive);
            Assert.True(vm.IsIncidentsTabActive);

            // Switch back to Quarantine tab via command
            vm.SelectQuarantineTabCommand.Execute(null);
            Assert.True(vm.IsQuarantineTabActive);
            Assert.False(vm.IsIncidentsTabActive);

            // Direct TwoWay binding property changes
            vm.IsIncidentsTabActive = true;
            Assert.False(vm.IsQuarantineTabActive);
            Assert.True(vm.IsIncidentsTabActive);

            vm.IsQuarantineTabActive = true;
            Assert.True(vm.IsQuarantineTabActive);
            Assert.False(vm.IsIncidentsTabActive);
        }
    }
}
