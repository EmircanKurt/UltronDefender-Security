using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Core.Enums;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AegisPC.Tests;

[Collection("SequentialDiskTests")]
public sealed class QuarantineStructuredRiskTests : IDisposable
{
    private readonly string _sandboxDirectory = Path.Combine(Path.GetTempPath(),
        "AegisStructuredRisk_" + Guid.NewGuid().ToString("N"));

    public QuarantineStructuredRiskTests() => Directory.CreateDirectory(_sandboxDirectory);

    [Theory]
    [InlineData("EICAR test label")]
    [InlineData("Ransom activity label")]
    [InlineData("Mimikatz label")]
    public async Task LegacyReasonWords_DoNotClaimConfirmedMalicious(string reason)
    {
        using var engine = CreateEngine();
        var path = await CreateBenignFileAsync();

        var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
        {
            TargetFilePath = path,
            ThreatReason = reason,
            ForceKillHoldingProcesses = false
        });

        Assert.True(result.Success, result.Message);
        var entry = await engine.GetItemByIdAsync(result.QuarantineId);
        Assert.NotNull(entry);
        Assert.Equal(RiskLevel.Unknown, entry.RiskLevel);
        Assert.Equal(reason, entry.Reason);
    }

    [Theory]
    [InlineData(QuarantineDetectionEvidenceKind.VerifiedKnownMaliciousHash)]
    [InlineData(QuarantineDetectionEvidenceKind.VerifiedContentSignature)]
    public async Task ForgedVerifiedEvidenceForBenignContent_RecordsUnknown(QuarantineDetectionEvidenceKind kind)
    {
        using var engine = CreateEngine();
        var path = await CreateBenignFileAsync();
        var hash = await ComputeSha256Async(path);

        var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
        {
            TargetFilePath = path,
            ThreatReason = "Arbitrary neutral description",
            ExpectedSha256 = hash,
            DetectionEvidence = new QuarantineDetectionEvidence
            {
                Kind = kind,
                ContentSha256 = hash
            },
            ForceKillHoldingProcesses = false
        });

        Assert.True(result.Success, result.Message);
        var entry = await engine.GetItemByIdAsync(result.QuarantineId);
        Assert.NotNull(entry);
        Assert.Equal(RiskLevel.Unknown, entry.RiskLevel);
    }

    [Fact]
    public async Task EvidenceForDifferentContent_RecordsUnknownRisk()
    {
        using var engine = CreateEngine();
        var path = await CreateBenignFileAsync();
        var differentHash = new string('A', 64);

        var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
        {
            TargetFilePath = path,
            ThreatReason = "Ransom",
            DetectionEvidence = new QuarantineDetectionEvidence
            {
                Kind = QuarantineDetectionEvidenceKind.VerifiedContentSignature,
                ContentSha256 = differentHash
            },
            ForceKillHoldingProcesses = false
        });

        Assert.True(result.Success, result.Message);
        var entry = await engine.GetItemByIdAsync(result.QuarantineId);
        Assert.NotNull(entry);
        Assert.Equal(RiskLevel.Unknown, entry.RiskLevel);
    }

    [Fact]
    public async Task UnsupportedHeuristicEvidence_RecordsUnknown()
    {
        using var engine = CreateEngine();
        var path = await CreateBenignFileAsync();
        var hash = await ComputeSha256Async(path);

        var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
        {
            TargetFilePath = path,
            ThreatReason = "No display label assurance",
            DetectionEvidence = new QuarantineDetectionEvidence
            {
                Kind = QuarantineDetectionEvidenceKind.Heuristic,
                ContentSha256 = hash
            },
            ForceKillHoldingProcesses = false
        });

        Assert.True(result.Success, result.Message);
        var entry = await engine.GetItemByIdAsync(result.QuarantineId);
        Assert.NotNull(entry);
        Assert.Equal(RiskLevel.Unknown, entry.RiskLevel);
    }

    [Fact]
    public async Task ContentBoundLegacyServiceCall_DoesNotTreatHashOrReasonAsDetectionProof()
    {
        var path = await CreateBenignFileAsync();
        var hash = await ComputeSha256Async(path);
        using var service = new QuarantineService(new HashService(),
            customVaultDir: Path.Combine(_sandboxDirectory, "vault"));

        var quarantined = await service.TryQuarantineFileAsync(path, "EICAR Ransom Mimikatz", hash);

        Assert.True(quarantined, service.LastError);
        var entry = Assert.Single(await service.GetQuarantinedItemsAsync());
        Assert.Equal(RiskLevel.Unknown, entry.RiskLevel);
    }

    [Fact]
    public void KnownMalwareReferenceHash_IsConfirmedByProductionVerifierWithoutWritingPayload()
    {
        // Reference hash is already part of the production offline database. This tests
        // classification only; no EICAR content or real malware is written to disk.
        const string referenceHash = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
        Assert.True(MalwareSignatureDatabase.CheckHash(referenceHash).IsMatched);
        using var engine = CreateEngine();
        var resolver = typeof(TransactionalQuarantineEngine).GetMethod("ResolveRiskLevel",
            BindingFlags.Instance | BindingFlags.NonPublic);

        Assert.NotNull(resolver);
        var risk = resolver.Invoke(engine, new object?[] { null, referenceHash });
        Assert.Equal(RiskLevel.ConfirmedMalicious, Assert.IsType<RiskLevel>(risk));
    }

    private TransactionalQuarantineEngine CreateEngine() =>
        new(customVaultDir: Path.Combine(_sandboxDirectory, "vault"));

    private async Task<string> CreateBenignFileAsync()
    {
        var path = Path.Combine(_sandboxDirectory, Guid.NewGuid().ToString("N") + ".dat");
        await File.WriteAllBytesAsync(path, RandomNumberGenerator.GetBytes(64));
        return path;
    }

    private static async Task<string> ComputeSha256Async(string path) =>
        Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path)));

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_sandboxDirectory)) Directory.Delete(_sandboxDirectory, recursive: true);
    }
}
