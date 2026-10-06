using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AegisPC.Tests;

[Collection("SequentialDiskTests")]
public sealed class ReviewFixRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "Aegis_ReviewFix_" + Guid.NewGuid().ToString("N"));
    private string Vault => Path.Combine(_root, "Vault");
    public ReviewFixRegressionTests() => Directory.CreateDirectory(Vault);
    public void Dispose() { Directory.Delete(_root, recursive: true); }

    [Fact]
    public async Task SeparateEngines_ReserveDistinctDurableIds()
    {
        using var first = new TransactionalQuarantineEngine(customVaultDir: Vault);
        using var second = new TransactionalQuarantineEngine(customVaultDir: Vault);
        Assert.Equal(first.GetMasterKey(), second.GetMasterKey());
        var paths = Enumerable.Range(0, 12).Select(i => Path.Combine(_root, $"benign_{i}.txt")).ToArray();
        foreach (var path in paths) await File.WriteAllTextAsync(path, "BENIGN REVIEW FIXTURE");
        var results = await Task.WhenAll(paths.Select((path, i) => (i % 2 == 0 ? first : second)
            .ExecuteQuarantineAsync(new QuarantineRequest { TargetFilePath = path, ThreatReason = "Simulation", ForceKillHoldingProcesses = false })));
        Assert.All(results, r => Assert.True(r.Success, r.Message));
        Assert.Equal(paths.Length, results.Select(r => r.QuarantineId).Distinct().Count());
        using var restarted = new TransactionalQuarantineEngine(customVaultDir: Vault);
        Assert.True(restarted.Database.AllocateNextId() > results.Max(r => r.QuarantineId));
    }

    [Theory]
    [InlineData(DataProtectionScope.LocalMachine)]
    [InlineData(DataProtectionScope.CurrentUser)]
    public void GenuineLegacyEntropyLayout_OpensWithoutRewritingKey(DataProtectionScope scope)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var entropy = RandomNumberGenerator.GetBytes(32);
        var encrypted = ProtectedData.Protect(key, entropy, scope);
        File.WriteAllBytes(Path.Combine(Vault, "entropy.dat"), entropy);
        File.WriteAllBytes(Path.Combine(Vault, "vault.key"), encrypted);
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        Assert.Equal(key, engine.GetMasterKey());
        Assert.Equal(encrypted, File.ReadAllBytes(Path.Combine(Vault, "vault.key")));
        Assert.False(File.Exists(Path.Combine(Vault, "vault_entropy.dat")));
    }

    [Fact]
    public async Task DuplicateLegacyIds_PreserveBothRecordsAndOriginalBackup()
    {
        var entries = Enumerable.Range(1, 2).Select(i => new QuarantineEntry
        {
            Id = 7, OriginalPath = Path.Combine(_root, $"original_{i}.txt"),
            QuarantinePath = Path.Combine(Vault, $"legacy_{i}.quar"), FileName = $"original_{i}.txt",
            SHA256 = new string('a', 64), Reason = "Simulation", Status = QuarantineStatus.Quarantined,
            QuarantinedAt = DateTime.UtcNow
        }).ToArray();
        var index = Path.Combine(Vault, "quarantine_index.json");
        var json = JsonSerializer.Serialize(entries);
        await File.WriteAllTextAsync(index, json);
        using (var db = new QuarantineVaultDatabase(Vault))
        {
            var migrated = await db.GetAllEntriesAsync();
            Assert.Equal(2, migrated.Count);
            Assert.Equal(2, migrated.Select(e => e.Id).Distinct().Count());
        }
        using var reopened = new QuarantineVaultDatabase(Vault);
        Assert.Equal(2, (await reopened.GetAllEntriesAsync()).Count);
        Assert.Equal(json, await File.ReadAllTextAsync(index + ".migration-backup"));
    }

    [Fact]
    public async Task SourceSnapshot_DeniesWritersAndReplacementUntilDeletion()
    {
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var path = Path.Combine(_root, "document.txt");
        byte[] payload = new byte[8 * 1024 * 1024];
        payload[0] = 65;
        await File.WriteAllBytesAsync(path, payload);
        // Reserve before blocking the entry INSERT (ID allocation now also uses SQLite).
        // A large source yields during hashing, allowing the blocker to start first.
        var scan = engine.ExecuteQuarantineAsync(new QuarantineRequest
        { TargetFilePath = path, ThreatReason = "Simulation", ForceKillHoldingProcesses = false });
        using var connection = new SqliteConnection($"Data Source={Path.Combine(Vault, "QuarantineVault.db")};Pooling=False");
        connection.Open();
        using var transaction = connection.BeginTransaction();
        bool deniedWrite = false, deniedReplace = false;
        try
        {
            try { File.WriteAllText(path, "NEW DOCUMENT MUST NOT BE LOST"); }
            catch (IOException) { deniedWrite = true; }
            try { File.Move(path, path + ".replacement"); }
            catch (IOException) { deniedReplace = true; }
        }
        finally { transaction.Rollback(); }
        Assert.True(deniedWrite, "A writer was admitted while the quarantine snapshot was in progress.");
        Assert.True(deniedReplace, "The source identity could be replaced during quarantine.");
        var result = await scan;
        Assert.True(result.Success, result.Message);
        var restore = await engine.ExecuteRestoreAsync(result.QuarantineId);
        Assert.True(restore.Success, restore.Message);
        Assert.Equal(payload, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task IndexFault_LeavesNeitherDatabaseRowNorOrphanBlob()
    {
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var path = Path.Combine(_root, "safe.txt");
        await File.WriteAllTextAsync(path, "KEEP ME");
        Directory.CreateDirectory(Path.Combine(Vault, "quarantine_index.json"));
        var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
        { TargetFilePath = path, ThreatReason = "Simulation", ForceKillHoldingProcesses = false });
        Assert.False(result.Success);
        Assert.Equal("KEEP ME", await File.ReadAllTextAsync(path));
        Assert.Empty(await engine.Database.GetAllEntriesAsync());
        Assert.Empty(Directory.GetFiles(Vault, "*.quar"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(15)]
    [InlineData(25)]
    [InlineData(45)]
    [InlineData(55)]
    [InlineData(-1)]
    public async Task AuthenticatedVault_TamperingNeverEmitsPlaintext(int offset)
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        var vault = Path.Combine(Vault, "auth.quar");
        using var source = new MemoryStream(new byte[8192]);
        await VaultContainerCodec.EncryptToVaultV4Async(source, vault, key);
        byte[] bytes = await File.ReadAllBytesAsync(vault);
        bytes[offset < 0 ? bytes.Length - 1 : offset] ^= 1;
        await File.WriteAllBytesAsync(vault, bytes);
        using var output = new MemoryStream();
        Assert.False(await VaultContainerCodec.DecryptVaultStreamAsync(vault, output, key));
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public async Task LegacyV3Container_StillRestoresWithOriginalKeyLayout()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32), entropy = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(Path.Combine(Vault, "entropy.dat"), entropy);
        File.WriteAllBytes(Path.Combine(Vault, "vault.key"), ProtectedData.Protect(key, entropy, DataProtectionScope.LocalMachine));
        byte[] payload = System.Text.Encoding.UTF8.GetBytes("BENIGN LEGACY PAYLOAD");
        string original = Path.Combine(_root, "old.txt"), blob = Path.Combine(Vault, "old.quar");
        await File.WriteAllBytesAsync(original, payload);
        var info = await VaultContainerCodec.EncryptToVaultV3Async(original, blob, key);
        File.Delete(original);
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        await engine.Database.InsertEntryAsync(new QuarantineEntry
        { Id = 33, OriginalPath = original, QuarantinePath = blob, FileName = "old.txt", SHA256 = info.Sha256,
          FileSize = info.PlainSize, Reason = "Simulation", QuarantinedAt = DateTime.UtcNow, Status = QuarantineStatus.Quarantined }, original);
        var result = await engine.ExecuteRestoreAsync(33);
        Assert.True(result.Success, result.Message);
        Assert.Equal(payload, await File.ReadAllBytesAsync(original));
    }

    [Fact]
    public async Task ReadOnlySource_IsQuarantinedByIdentityWithoutPathAttributeChanges()
    {
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var path = Path.Combine(_root, "read-only.txt");
        await File.WriteAllTextAsync(path, "BENIGN READ ONLY FIXTURE");
        File.SetAttributes(path, FileAttributes.ReadOnly);
        try
        {
            var result = await engine.ExecuteQuarantineAsync(new QuarantineRequest
            { TargetFilePath = path, ThreatReason = "Simulation", ForceKillHoldingProcesses = false });
            Assert.True(result.Success, result.Message);
            Assert.False(File.Exists(path));
            Assert.True((await engine.ExecuteRestoreAsync(result.QuarantineId)).Success);
            Assert.Equal("BENIGN READ ONLY FIXTURE", await File.ReadAllTextAsync(path));
        }
        finally { if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal); }
    }
}
