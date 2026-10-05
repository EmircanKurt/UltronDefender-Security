using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Contracts.ThreatIntelligence;
using AegisPC.Core.Models;
using AegisPC.Security.Detection.Detectors;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Checks caller cancellation with an inert file and fake cloud service.</summary>
public sealed class HashDetectorCancellationTests
{
    [Fact]
    public async Task PreCancelledCallerPropagatesWithoutCloudLookup()
    {
        string path = Path.Combine(Path.GetTempPath(), "UltronHashCancel_" + Guid.NewGuid().ToString("N") + ".txt");
        await File.WriteAllTextAsync(path, "benign cancellation fixture");
        try
        {
            using var cts = new CancellationTokenSource();
            var detector = new HashSignatureDetector(new NoopHash(), new CancellingCloud(cts, path), new EmptyStore());
            var context = new DetectionContext { FilePath = path, SHA256 = new string('A', 64) };
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => detector.EvaluateAsync(context, cts.Token));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    private sealed class CancellingCloud(CancellationTokenSource source, string path) : IReputationService
    {
        public bool IsCloudLookupEnabled { get; set; } = true;
        public Task<ReputationResult> CheckReputationAsync(string sha256, CancellationToken cancellationToken = default)
        {
            File.Delete(path); // Ensure no later file-content path can accidentally surface the swallowed cancellation.
            source.Cancel();
            throw new OperationCanceledException(cancellationToken);
        }
    }

    private sealed class NoopHash : IHashService
    {
        public Task<string> ComputeSha256Async(string filePath, CancellationToken ct = default) => Task.FromResult(new string('A', 64));
        public Task<string> ComputeSha1Async(string filePath, CancellationToken ct = default) => Task.FromResult(new string('B', 40));
    }

    private sealed class EmptyStore : IThreatIntelligenceStore
    {
        public bool IsMaliciousHash(string sha256, out ThreatIntelRecord? record) { record = null; return false; }
        public bool IsTrustedHash(string sha256) => false;
        public bool IsTrustedPublisher(string? publisher) => false;
        public void RegisterMaliciousHash(string sha256, string threatName, string category = "Malware", int severity = 100) { }
        public void RegisterTrustedHash(string sha256) { }
        public int MaliciousSignaturesCount => 0;
        public int TrustedHashesCount => 0;
    }
}

