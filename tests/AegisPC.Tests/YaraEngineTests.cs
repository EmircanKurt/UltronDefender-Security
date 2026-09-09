using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Detection.YaraEngine;
using Xunit;

namespace AegisPC.Tests
{
    public class YaraEngineTests : IDisposable
    {
        private readonly string _tempRulesDir;
        private readonly YaraEngine _yaraEngine;

        public const string EicarStandardString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        public YaraEngineTests()
        {
            _tempRulesDir = Path.Combine(Path.GetTempPath(), $"AegisPC_YaraTest_{Guid.NewGuid():N}");
            Directory.CreateDirectory(_tempRulesDir);
            _yaraEngine = new YaraEngine(_tempRulesDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempRulesDir))
                {
                    Directory.Delete(_tempRulesDir, true);
                }
            }
            catch
            {
                // Test cleanup
            }
        }

        [Fact]
        public void YaraEngine_Initialization_LoadsDefaultThreeRules()
        {
            // Assert: eicar.yar, mimikatz.yar, cobaltstrike.yar
            Assert.True(_yaraEngine.LoadedRuleCount >= 3, $"En az 3 kural yüklenmiş olmalı. Bulunan: {_yaraEngine.LoadedRuleCount}");
            Assert.True(File.Exists(Path.Combine(_tempRulesDir, "eicar.yar")));
            Assert.True(File.Exists(Path.Combine(_tempRulesDir, "mimikatz.yar")));
            Assert.True(File.Exists(Path.Combine(_tempRulesDir, "cobaltstrike.yar")));
        }

        [Fact]
        public async Task ScanBuffer_EicarStandardString_DetectsWithExactOffset()
        {
            // Arrange: 128 baytlık ön ek (padding) ve ardından EICAR stringi
            byte[] prefix = Encoding.ASCII.GetBytes("This is benign padding header before malware string.");
            byte[] eicar = Encoding.ASCII.GetBytes(EicarStandardString);
            byte[] buffer = new byte[prefix.Length + eicar.Length + 64];

            Array.Copy(prefix, 0, buffer, 0, prefix.Length);
            long expectedOffset = prefix.Length;
            Array.Copy(eicar, 0, buffer, expectedOffset, eicar.Length);

            // Act
            var matches = await _yaraEngine.ScanBufferAsync(buffer, "eicar_test.dat");

            // Assert
            Assert.NotEmpty(matches);
            var eicarMatch = matches.FirstOrDefault(m => m.RuleName.Contains("EICAR", StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(eicarMatch);
            Assert.Equal(100, eicarMatch.Severity);
            Assert.NotEmpty(eicarMatch.MatchedStrings);

            var stringMatch = eicarMatch.MatchedStrings.First();
            Assert.Equal(expectedOffset, stringMatch.Offset);
            Assert.Equal("$eicar", stringMatch.Identifier);
        }

        [Fact]
        public async Task ScanBuffer_CleanBenignContent_ReturnsZeroMatches()
        {
            // Arrange
            byte[] cleanData = Encoding.UTF8.GetBytes("Normal user document with benign text and no exploit payload whatsoever.");

            // Act
            var matches = await _yaraEngine.ScanBufferAsync(cleanData, "clean.txt");

            // Assert
            Assert.Empty(matches);
        }

        [Fact]
        public async Task ScanBuffer_MimikatzSekurlsaPattern_DetectsCaseInsensitive()
        {
            // Arrange
            string mixedCasePayload = "Binary dummy ... SEKURLSA::LogonPasswords ... payload end";
            byte[] buffer = Encoding.ASCII.GetBytes(mixedCasePayload);
            long expectedOffset = mixedCasePayload.IndexOf("SEKURLSA", StringComparison.OrdinalIgnoreCase);

            // Act
            var matches = await _yaraEngine.ScanBufferAsync(buffer, "mimikatz_test.bin");

            // Assert
            Assert.NotEmpty(matches);
            var mimiMatch = matches.FirstOrDefault(m => m.RuleName.Contains("Mimikatz", StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(mimiMatch);
            Assert.Equal(100, mimiMatch.Severity);

            var strMatch = mimiMatch.MatchedStrings.FirstOrDefault(s => s.Identifier == "$s1");
            Assert.NotNull(strMatch);
            Assert.Equal(expectedOffset, strMatch.Offset);
        }

        [Fact]
        public async Task ScanBuffer_CobaltStrikePipe_DetectsNamedPipeIndicator()
        {
            // Arrange
            string pipeSample = "cmd.exe /c echo test > \\\\.\\pipe\\msagent_1234";
            byte[] buffer = Encoding.ASCII.GetBytes(pipeSample);
            long expectedOffset = pipeSample.IndexOf("\\pipe\\msagent_", StringComparison.OrdinalIgnoreCase);

            // Act
            var matches = await _yaraEngine.ScanBufferAsync(buffer, "cs_sample.exe");

            // Assert
            Assert.NotEmpty(matches);
            var csMatch = matches.FirstOrDefault(m => m.RuleName.Contains("CobaltStrike", StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(csMatch);
            Assert.Contains(csMatch.MatchedStrings, s => s.Offset == expectedOffset);
        }

        [Fact]
        public async Task YaraDetector_EvaluateAsync_GeneratesSecurityEvidenceWithOffsets()
        {
            // Arrange
            string tempFile = Path.Combine(_tempRulesDir, $"test_eicar_{Guid.NewGuid():N}.com");
            await File.WriteAllTextAsync(tempFile, EicarStandardString);

            try
            {
                var detector = new YaraDetector(_yaraEngine);
                var context = new DetectionContext { FilePath = tempFile };

                // Act
                var evidences = (await detector.EvaluateAsync(context)).ToList();

                // Assert
                Assert.NotEmpty(evidences);
                var ev = evidences.First();
                Assert.Equal(EvidenceCategory.StaticSignature, ev.Category);
                Assert.Equal(EvidenceConfidence.Absolute, ev.Confidence);
                Assert.Equal(100, ev.ScoreContribution);
                Assert.Contains("EICAR", ev.RuleName);
                Assert.True(ev.Metadata.ContainsKey("MatchedOffsets"));
                Assert.True(ev.Metadata.ContainsKey("PrimaryOffset"));
                Assert.Equal("0x00000000", ev.Metadata["PrimaryOffset"]);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public async Task DetectionHub_IncludesYaraDetector_DetectsThreat()
        {
            // Arrange
            var hub = DetectionHubFactory.CreateDefault(yaraEngine: _yaraEngine);
            string tempFile = Path.Combine(_tempRulesDir, $"hub_test_{Guid.NewGuid():N}.com");
            await File.WriteAllTextAsync(tempFile, EicarStandardString);

            try
            {
                var context = new DetectionContext { FilePath = tempFile };

                // Act
                var result = await hub.EvaluateAsync(context);

                // Assert
                Assert.True(result.RiskScore >= 70);
                Assert.Contains(result.Evidences, e => e.RuleName.StartsWith("Yara.", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }
    }
}
