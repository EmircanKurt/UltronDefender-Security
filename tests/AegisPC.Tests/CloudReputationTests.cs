using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Detection.Detectors;
using AegisPC.Security.Reputation;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests
{
    [Collection("SequentialDiskTests")]
    public class CloudReputationTests : IDisposable
    {
        private readonly string _sandboxDir;

        public CloudReputationTests()
        {
            _sandboxDir = Path.Combine(Path.GetTempPath(), "Aegis_CloudRep_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_sandboxDir);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_sandboxDir))
                {
                    Directory.Delete(_sandboxDir, true);
                }
            }
            catch { }
        }

        [Fact]
        public async Task ReputationService_WhenDisabled_ReturnsOfflineSafeResultWithoutCallingHttp()
        {
            var testHandler = new MockHttpMessageHandler((req, ct) =>
                throw new InvalidOperationException("HTTP call should not be made when disabled!"));

            using var httpClient = new HttpClient(testHandler);
            using var reputationService = new ReputationService(httpClient: httpClient)
            {
                IsCloudLookupEnabled = false
            };

            var result = await reputationService.CheckReputationAsync("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

            Assert.NotNull(result);
            Assert.False(result.IsKnown);
            Assert.False(result.IsMalicious);
            Assert.Contains("devre dışı", result.Details);
            Assert.Equal(0, testHandler.CallCount);
        }

        [Fact]
        public async Task ReputationService_WhenEmptyOrZeroByteHash_ReturnsCleanImmediate()
        {
            var testHandler = new MockHttpMessageHandler((req, ct) =>
                throw new InvalidOperationException("HTTP call should not be made for empty hash!"));

            using var httpClient = new HttpClient(testHandler);
            using var reputationService = new ReputationService(httpClient: httpClient)
            {
                IsCloudLookupEnabled = true
            };

            // Empty hash string
            var res1 = await reputationService.CheckReputationAsync("");
            Assert.False(res1.IsMalicious);

            // Standard empty file SHA-256
            var res2 = await reputationService.CheckReputationAsync("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            Assert.False(res2.IsMalicious);
            Assert.Contains("0 byte", res2.Details);
            Assert.Equal(0, testHandler.CallCount);
        }

        [Fact]
        public async Task ReputationService_MalwareBazaar_ConfirmedMalicious_AutoLearnsAndCaches()
        {
            string fakeSha = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            string mbResponseJson = $$"""
            {
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "{{fakeSha}}",
                        "signature": "AsyncRAT",
                        "file_type": "exe",
                        "tags": ["AsyncRAT", "rat", "stealer"]
                    }
                ]
            }
            """;

            var testHandler = new MockHttpMessageHandler((req, ct) =>
            {
                var resp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(mbResponseJson, Encoding.UTF8, "application/json")
                };
                return Task.FromResult(resp);
            });

            using var httpClient = new HttpClient(testHandler);
            using var reputationService = new ReputationService(httpClient: httpClient)
            {
                IsCloudLookupEnabled = true
            };

            // First call: Should hit HTTP and parse
            var result = await reputationService.CheckReputationAsync(fakeSha);

            Assert.NotNull(result);
            Assert.True(result.IsKnown);
            Assert.True(result.IsMalicious);
            Assert.Equal("AsyncRAT", result.ThreatName);
            Assert.Equal(100, result.Severity);
            Assert.Contains("AsyncRAT", result.Tags);
            Assert.Equal(1, testHandler.CallCount);

            // Second call: Should return from memory cache with O(1) speed, 0 new HTTP calls
            var cachedResult = await reputationService.CheckReputationAsync(fakeSha);
            Assert.True(cachedResult.IsMalicious);
            Assert.Equal(1, testHandler.CallCount); // Still 1!
        }

        [Fact]
        public async Task ReputationService_MalwareBazaar_HashNotFound_CachesAsClean()
        {
            string fakeSha = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            string mbNotFoundJson = """
            {
                "query_status": "hash_not_found"
            }
            """;

            var testHandler = new MockHttpMessageHandler((req, ct) =>
            {
                var resp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(mbNotFoundJson, Encoding.UTF8, "application/json")
                };
                return Task.FromResult(resp);
            });

            using var httpClient = new HttpClient(testHandler);
            using var reputationService = new ReputationService(httpClient: httpClient)
            {
                IsCloudLookupEnabled = true
            };

            var result = await reputationService.CheckReputationAsync(fakeSha);

            Assert.NotNull(result);
            Assert.True(result.IsKnown);
            Assert.False(result.IsMalicious);
            Assert.Equal(1, testHandler.CallCount);

            // Check cache
            var secondResult = await reputationService.CheckReputationAsync(fakeSha);
            Assert.False(secondResult.IsMalicious);
            Assert.Equal(1, testHandler.CallCount); // Still 1!
        }

        [Fact]
        public async Task ReputationService_NetworkErrorOrTimeout_GracefulDegradation()
        {
            string fakeSha = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");

            var testHandler = new MockHttpMessageHandler((req, ct) =>
            {
                throw new HttpRequestException("Simulated network outage (DNS resolution failure)");
            });

            using var httpClient = new HttpClient(testHandler);
            using var reputationService = new ReputationService(httpClient: httpClient)
            {
                IsCloudLookupEnabled = true
            };

            // Should NEVER throw exception, smoothly returns clean fallback
            var result = await reputationService.CheckReputationAsync(fakeSha);

            Assert.NotNull(result);
            Assert.False(result.IsMalicious);
            Assert.Contains("ulaşılamadı", result.Details);
        }

        [Fact]
        public async Task HashSignatureDetector_WithCloudReputation_DetectsMaliciousHash()
        {
            string fakeSha = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            string testFile = Path.Combine(_sandboxDir, "sample_threat.exe");
            await File.WriteAllBytesAsync(testFile, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 });

            var mockRepService = new MockReputationService
            {
                IsCloudLookupEnabled = true,
                ResultToReturn = new ReputationResult
                {
                    IsKnown = true,
                    IsMalicious = true,
                    ThreatName = "AgentTesla.Stealer",
                    Severity = 100,
                    MalwareFamily = "AgentTesla",
                    Source = "Abuse.ch MalwareBazaar Cloud"
                }
            };

            var mockHashService = new MockHashService(fakeSha);
            var detector = new HashSignatureDetector(mockHashService, mockRepService);

            var context = new DetectionContext
            {
                FilePath = testFile,
                SHA256 = fakeSha
            };

            var evidences = (await detector.EvaluateAsync(context)).ToList();

            Assert.NotEmpty(evidences);
            var cloudEvidence = evidences.FirstOrDefault(e => e.RuleName.StartsWith("Signature.Cloud"));
            Assert.NotNull(cloudEvidence);
            Assert.Equal(100, cloudEvidence.ScoreContribution);
            Assert.Contains("AgentTesla", cloudEvidence.Description);
            Assert.Equal(EvidenceConfidence.Absolute, cloudEvidence.Confidence);
        }

        // Mock HTTP Handler
        private class MockHttpMessageHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _handler;
            public int CallCount { get; private set; }

            public MockHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
            {
                _handler = handler;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                CallCount++;
                return _handler(request, cancellationToken);
            }
        }

        // Mock Reputation Service
        private class MockReputationService : IReputationService
        {
            public bool IsCloudLookupEnabled { get; set; } = true;
            public ReputationResult ResultToReturn { get; set; } = new() { IsKnown = false, IsMalicious = false };

            public Task<ReputationResult> CheckReputationAsync(string sha256, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(ResultToReturn);
            }
        }

        // Mock Hash Service
        private class MockHashService : IHashService
        {
            private readonly string _fixedHash;
            public MockHashService(string fixedHash) => _fixedHash = fixedHash;
            public Task<string> ComputeSha256Async(string filePath, CancellationToken ct = default) => Task.FromResult(_fixedHash);
            public Task<string> ComputeSha1Async(string filePath, CancellationToken ct = default) => Task.FromResult("dummy_sha1");
        }
    }
}
