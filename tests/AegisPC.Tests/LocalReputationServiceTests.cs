using System;
using System.IO;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Security.Reputation;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    public class LocalReputationServiceTests : IDisposable
    {
        private readonly string _testDir;

        public LocalReputationServiceTests()
        {
            _testDir = Path.Combine(Path.GetTempPath(), "AegisPC_RepTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_testDir))
                {
                    Directory.Delete(_testDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task LocalReputation_NewFile_HasZeroDiscount()
        {
            var service = new LocalReputationService(customStoragePath: _testDir);
            string hash = "abc123hash";

            await service.RecordFileObservationAsync(@"C:\app.exe", hash, "explorer.exe");

            var verdict = await service.EvaluateReputationAsync(hash);
            Assert.Equal(0, verdict.ScoreModifier);
            Assert.False(verdict.IsLongTermClean);
        }

        [Fact]
        public async Task LocalReputation_SixMonthsCleanFile_GrantsTenPointDiscount()
        {
            var service = new LocalReputationService(customStoragePath: _testDir);
            string hash = "cleanolderfilehash";

            // Record observation
            await service.RecordFileObservationAsync(@"C:\Program Files\OldApp\tool.exe", hash, "installer.exe");

            // Simulate file first seen 200 days ago
            var record = new LocalReputationRecord
            {
                SHA256 = hash,
                FilePath = @"C:\Program Files\OldApp\tool.exe",
                FirstSeenUtc = DateTime.UtcNow.AddDays(-200),
                LastSeenUtc = DateTime.UtcNow,
                HasMaliciousIncident = false
            };

            // Save and reload
            string json = System.Text.Json.JsonSerializer.Serialize(new[] { record });
            await File.WriteAllTextAsync(Path.Combine(_testDir, "local_reputation.json"), json);

            var reloadedService = new LocalReputationService(customStoragePath: _testDir);
            var verdict = await reloadedService.EvaluateReputationAsync(hash);

            Assert.Equal(-10, verdict.ScoreModifier);
            Assert.True(verdict.IsLongTermClean);
            Assert.True(verdict.AgeDays >= 199);
            Assert.Contains("-10 Yerel İtibar", verdict.Reason);
        }

        [Fact]
        public async Task LocalReputation_FileWithIncident_RevokesCleanDiscount()
        {
            string hash = "compromisedfilehash";
            var record = new LocalReputationRecord
            {
                SHA256 = hash,
                FilePath = @"C:\app.exe",
                FirstSeenUtc = DateTime.UtcNow.AddDays(-200),
                HasMaliciousIncident = false
            };

            string json = System.Text.Json.JsonSerializer.Serialize(new[] { record });
            await File.WriteAllTextAsync(Path.Combine(_testDir, "local_reputation.json"), json);

            var service = new LocalReputationService(customStoragePath: _testDir);

            // Record incident
            await service.RecordIncidentAsync(hash);

            var verdict = await service.EvaluateReputationAsync(hash);
            Assert.Equal(0, verdict.ScoreModifier);
            Assert.False(verdict.IsLongTermClean);
        }

        [Fact]
        public async Task RiskScoringEngine_WithLocalReputationService_AppliesDiscount()
        {
            string hash = "hash_with_local_discount";
            var record = new LocalReputationRecord
            {
                SHA256 = hash,
                FilePath = @"C:\test.exe",
                FirstSeenUtc = DateTime.UtcNow.AddDays(-200),
                HasMaliciousIncident = false
            };

            string json = System.Text.Json.JsonSerializer.Serialize(new[] { record });
            await File.WriteAllTextAsync(Path.Combine(_testDir, "local_reputation.json"), json);

            var repService = new LocalReputationService(customStoragePath: _testDir);
            var scoringEngine = new RiskScoringEngine(repService);

            var fileAnalysis = new FileAnalysisResult
            {
                FilePath = @"C:\test.exe",
                FileName = "test.exe",
                SHA256 = hash,
                IsExecutable = true,
                Entropy = 4.0
            };

            var (score, level, reasons) = await scoringEngine.CalculateRiskScoreAsync(fileAnalysis);

            Assert.Contains(reasons, r => r.Contains("-10 Yerel İtibar"));
        }
    }
}
