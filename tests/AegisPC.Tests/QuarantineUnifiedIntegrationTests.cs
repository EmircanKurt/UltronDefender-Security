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

        [Fact]
        public async Task QuarantineUnified_RemoveAllFromQuarantine_RestoresOrPurgesAllItems_AndPersists()
        {
            // 1. Create 3 test quarantined files
            var file1 = Path.Combine(_testRoot, "threat1.dll");
            var file2 = Path.Combine(_testRoot, "threat2.exe");
            var file3 = Path.Combine(_testRoot, "threat3.bin");

            await File.WriteAllBytesAsync(file1, new byte[] { 0x4D, 0x5A, 0x01 });
            await File.WriteAllBytesAsync(file2, new byte[] { 0x4D, 0x5A, 0x02 });
            await File.WriteAllBytesAsync(file3, new byte[] { 0x4D, 0x5A, 0x03 });

            await _quarantineService.QuarantineFileAsync(file1, "Test.Threat.1");
            await _quarantineService.QuarantineFileAsync(file2, "Test.Threat.2");
            await _quarantineService.QuarantineFileAsync(file3, "Test.Threat.3");

            // Verify files moved to quarantine and deleted from source
            Assert.False(File.Exists(file1));
            Assert.False(File.Exists(file2));
            Assert.False(File.Exists(file3));

            // 2. Initialize ViewModel with quarantine service
            var vm = new QuarantineViewModel(quarantineService: _quarantineService);
            await vm.RefreshAllDataAsync();

            Assert.Equal(3, vm.QuarantinedItems.Count);
            Assert.True(vm.CanRemoveAll, "CanRemoveAll must be true when there are items in quarantine.");

            // 3. Execute Remove All
            await vm.RemoveAllFromQuarantineAsync();

            // 4. Verify in-memory state
            Assert.Empty(vm.QuarantinedItems);
            Assert.False(vm.CanRemoveAll, "CanRemoveAll must be false when quarantine is empty.");
            Assert.True(vm.HasNoQuarantinedItems);

            // 5. Verify physical restoration back to disk
            Assert.True(File.Exists(file1), "File 1 must be restored back to disk.");
            Assert.True(File.Exists(file2), "File 2 must be restored back to disk.");
            Assert.True(File.Exists(file3), "File 3 must be restored back to disk.");

            // 6. Verify persistence: reload fresh QuarantineService from vault disk index
            var freshService = new QuarantineService(hashService: new HashService(), customVaultDir: _vaultDir);
            var reloadedItems = await freshService.GetQuarantinedItemsAsync();
            Assert.Empty(reloadedItems);
        }

        [Fact]
        public async Task QuarantineUnified_RemediateIncident_RemovesIncidentFromListAndPurgesFromVault_AndPersists()
        {
            // 1. Create and quarantine a test threat file
            var threatFile = Path.Combine(_testRoot, "malicious_script.vbs");
            await File.WriteAllBytesAsync(threatFile, new byte[] { 0x58, 0x59, 0x5A });

            await _quarantineService.QuarantineFileAsync(threatFile, "Trojan.VbsRunner");
            Assert.False(File.Exists(threatFile));

            // 2. Initialize ViewModel and refresh
            var vm = new QuarantineViewModel(quarantineService: _quarantineService);
            await vm.RefreshAllDataAsync();

            Assert.Single(vm.QuarantinedItems);
            Assert.Single(vm.Incidents);
            Assert.False(vm.HasNoIncidents);

            var incidentToRemediate = vm.Incidents.First();
            Assert.StartsWith("QUAR-", incidentToRemediate.IncidentId);

            // 3. User clicks "Çözüldü Olarak İşaretle"
            await vm.RemediateIncidentAsync(incidentToRemediate);

            // 4. VERIFY: Immediately removed from incidents list and active incident count is 0
            Assert.Empty(vm.Incidents);
            Assert.True(vm.HasNoIncidents, "HasNoIncidents must be true once all incidents are remediated.");
            Assert.Equal(0, vm.ActiveIncidentCount);
            Assert.Null(vm.SelectedIncident);

            // 5. VERIFY: Quarantine vault is cleaned up
            Assert.Empty(vm.QuarantinedItems);
            Assert.True(vm.HasNoQuarantinedItems);

            // 6. VERIFY: Reloading incidents does NOT bring it back (anti-ghosting)
            await vm.LoadIncidentsAsync();
            Assert.Empty(vm.Incidents);
            Assert.True(vm.HasNoIncidents);
        }
    }
}
