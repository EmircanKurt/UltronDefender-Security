using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Safety;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using AegisPC.Security.Safety;
using AegisPC.Security.Scanning;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert temporary vault fixtures verify owner enforcement and streaming recovery without installing a service.</summary>
public sealed class QuarantineOwnershipSafetyTests : IDisposable
{
    private const string Alice = "S-1-5-21-100-200-300-1001";
    private const string Bob = "S-1-5-21-100-200-300-1002";
    private readonly string _root = Path.Combine(Path.GetTempPath(), "UltronVaultOwners_" + Guid.NewGuid().ToString("N"));
    private string Vault => Path.Combine(_root, "vault");

    /// <summary>Creates only this test's uniquely named temporary fixture root.</summary>
    public QuarantineOwnershipSafetyTests() => Directory.CreateDirectory(_root);

    [Fact]
    public async Task PersistedOwnerComesFromLockedSourceRatherThanReasonText()
    {
        string source = Fixture("owned.txt");
        string owner = new FileInfo(source).GetAccessControl().GetOwner(typeof(SecurityIdentifier))?.Value
            ?? throw new InvalidOperationException("Fixture ownership is unavailable.");
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var result = await engine.ExecuteQuarantineAsync(await Request(source, "OwnerSid=" + Bob));
        Assert.True(result.Success, result.Message);
        var entry = await engine.GetItemByIdAsync(result.QuarantineId);
        Assert.Equal(owner, entry!.OwnerSid);
        Assert.NotEqual(Bob, entry.OwnerSid);
    }

    [Fact]
    public async Task OtherOwnerCannotContainSourceEvenWithCorrectHash()
    {
        string source = Fixture("owned.txt");
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var result = await engine.ExecuteQuarantineForCallerAsync(await Request(source), Bob, false);
        Assert.False(result.Success);
        Assert.True(File.Exists(source));
        Assert.Empty(await engine.GetQuarantinedItemsAsync());
    }

    [Fact]
    public async Task OwnerListsDoNotExposeOtherOrUnassignedRecords()
    {
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        await engine.Database.InsertEntryAsync(Metadata(1, Alice), "first");
        await engine.Database.InsertEntryAsync(Metadata(2, Bob), "second");
        await engine.Database.InsertEntryAsync(Metadata(3, null), "legacy");
        Assert.Equal(1, Assert.Single(await engine.GetItemsForCallerAsync(Alice, false)).Id);
        Assert.Equal(2, Assert.Single(await engine.GetItemsForCallerAsync(Bob, false)).Id);
        Assert.Equal(3, (await engine.GetItemsForCallerAsync(Alice, true)).Count);
    }

    [Theory]
    [InlineData(Alice)]
    [InlineData(null)]
    public async Task UnauthorizedRestoreCannotInvokeDestinationWriter(string? owner)
    {
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        await engine.Database.InsertEntryAsync(Metadata(1, owner), "entry");
        bool invoked = false;
        var result = await engine.ExecuteRestoreForCallerAsync(1, Bob, false, (_, _, _) => { invoked = true; return Task.CompletedTask; });
        Assert.False(result.Success);
        Assert.False(invoked);
        Assert.Equal(QuarantineStatus.Quarantined, (await engine.GetItemByIdAsync(1))!.Status);
        Assert.False(await engine.DeleteForCallerAsync(1, Bob, false));
    }

    [Fact]
    public async Task StreamingWriterReceivesVerifiedBytesAndPostCommitCancellationDoesNotUndoMetadata()
    {
        string source = Fixture("owned.txt");
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var captured = await engine.ExecuteQuarantineAsync(await Request(source));
        var entry = await engine.GetItemByIdAsync(captured.QuarantineId);
        using var cancellation = new CancellationTokenSource();
        string destination = Path.Combine(_root, "restored.txt");
        var result = await engine.ExecuteRestoreForCallerAsync(captured.QuarantineId, entry!.OwnerSid!, false,
            async (metadata, bytes, ct) =>
            {
                Assert.Equal(destination, metadata.OriginalPath);
                Assert.Equal(entry.FileSize, bytes.Length);
                await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await bytes.CopyToAsync(output, ct);
                cancellation.Cancel();
            }, destination, cancellation.Token);
        Assert.True(result.Success, result.Message);
        Assert.Equal("Inert owned fixture data.", await File.ReadAllTextAsync(destination));
        Assert.Equal(QuarantineStatus.Restored, (await engine.GetItemByIdAsync(captured.QuarantineId))!.Status);
        Assert.Empty(Directory.GetFiles(Vault, "verified-restore.*.tmp"));
    }

    [Fact]
    public async Task TwoEngineInstancesReturnOneVerifiedRecoveryRecordForSamePathHash()
    {
        string source = Fixture("same.txt");
        var request = await Request(source);
        using var first = new TransactionalQuarantineEngine(customVaultDir: Vault);
        using var second = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var results = await Task.WhenAll(first.ExecuteQuarantineAsync(request), second.ExecuteQuarantineAsync(request));
        Assert.All(results, r => Assert.True(r.Success, r.Message));
        Assert.Equal(results[0].QuarantineId, results[1].QuarantineId);
        Assert.Single(await first.GetQuarantinedItemsAsync());
        Assert.Single(results.Where(r => r.WasAlreadyQuarantined));
        Assert.False(File.Exists(source));
    }

    [Fact]
    public void LegacyExplicitLockPermissionsAreReplacedThroughHeldHandles()
    {
        Directory.CreateDirectory(Vault);
        foreach (string name in new[] { "vault.operations.lock", "vault.init.lock" })
        {
            string path = Path.Combine(Vault, name);
            File.WriteAllText(path, string.Empty);
            var acl = new FileSecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(WindowsIdentity.GetCurrent().User!);
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
        }
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        foreach (string name in new[] { "vault.operations.lock", "vault.init.lock" })
        {
            var acl = new FileInfo(Path.Combine(Vault, name)).GetAccessControl();
            Assert.True(acl.AreAccessRulesProtected);
            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>();
            Assert.DoesNotContain(rules, r => r.IdentityReference.Value == "S-1-1-0");
            Assert.All(rules, r => Assert.Equal(AccessControlType.Allow, r.AccessControlType));
        }
    }

    [Fact(Skip = "VM gate: requires SeCreateSymbolicLinkPrivilege; this test token returned ERROR_PRIVILEGE_NOT_HELD (1314). Host policy must not be changed.")]
    /// <summary>VM-only native symlink gate; deliberately skipped locally rather than treating missing privilege as success.</summary>
    public void LegacyInitializationLockCannotRedirectCreationOutsideVault()
    {
        Directory.CreateDirectory(Vault);
        string target = Path.Combine(_root, "redirect-target.txt");
        File.CreateSymbolicLink(Path.Combine(Vault, "vault.init.lock"), target);
        Assert.ThrowsAny<IOException>(() => new TransactionalQuarantineEngine(customVaultDir: Vault));
        Assert.False(File.Exists(target));
    }

    [Fact]
    /// <summary>Rejects a real NTFS hardlinked lock before changing the outside-vault fixture's ACL or contents.</summary>
    public void LegacyOperationLockHardLinkCannotChangeFixtureTarget()
    {
        Directory.CreateDirectory(Vault);
        string target = Fixture("hardlink-target.txt");
        string? owner = new FileInfo(target).GetAccessControl().GetOwner(typeof(SecurityIdentifier))?.Value;
        bool created = CreateHardLinkW(Path.Combine(Vault, "vault.operations.lock"), target, IntPtr.Zero);
        int nativeError = Marshal.GetLastWin32Error();
        Assert.True(created, "The inert NTFS hardlink fixture could not be created; native error: " + nativeError);
        var exception = Assert.ThrowsAny<IOException>(() => new TransactionalQuarantineEngine(customVaultDir: Vault));
        Assert.Contains("single-link", exception.Message);
        Assert.Equal("Inert owned fixture data.", File.ReadAllText(target));
        Assert.Equal(owner, new FileInfo(target).GetAccessControl().GetOwner(typeof(SecurityIdentifier))?.Value);
    }

    [Fact]
    public async Task CancellationBeforeDeletionPreservesRecoveryCopyAndStatus()
    {
        string source = Fixture("cancel-delete.txt");
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var captured = await engine.ExecuteQuarantineAsync(await Request(source));
        Assert.True(captured.Success, captured.Message);
        var entry = (await engine.GetItemByIdAsync(captured.QuarantineId))!;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            engine.DeleteForCallerAsync(entry.Id, entry.OwnerSid!, false, cancellation.Token));
        Assert.True(File.Exists(entry.QuarantinePath));
        Assert.Equal(QuarantineStatus.Quarantined, (await engine.GetItemByIdAsync(entry.Id))!.Status);
    }

    [Fact]
    public async Task DeletedPayloadIsNotReportedUnchangedWhenMetadataCommitFails()
    {
        string source = Fixture("delete-metadata-failure.txt");
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var captured = await engine.ExecuteQuarantineAsync(await Request(source));
        Assert.True(captured.Success, captured.Message);
        var entry = (await engine.GetItemByIdAsync(captured.QuarantineId))!;
        using (var connection = new SqliteConnection("Data Source=" + Path.Combine(Vault, "QuarantineVault.db") + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TRIGGER fail_deleted_update BEFORE UPDATE OF Status ON QuarantineEntries " +
                "WHEN NEW.Status = 2 BEGIN SELECT RAISE(ABORT, 'Inert metadata failure fixture'); END;";
            command.ExecuteNonQuery();
        }
        Assert.True(await engine.DeleteForCallerAsync(entry.Id, entry.OwnerSid!, false));
        Assert.False(File.Exists(entry.QuarantinePath));
        // The action result is truthful; the explicit metadata failure still needs recovery reconciliation.
        Assert.Equal(QuarantineStatus.Quarantined, (await engine.GetItemByIdAsync(entry.Id))!.Status);
    }

    [Theory]
    [InlineData("vault.key")]
    [InlineData("vault_entropy.dat")]
    [InlineData("entropy.dat")]
    public void OversizedLegacyKeyStateFailsClosedWithoutReplacingBytes(string name)
    {
        using (var initial = new TransactionalQuarantineEngine(customVaultDir: Vault)) { }
        string path = Path.Combine(Vault, name);
        byte[] oversized = new byte[8193];
        File.WriteAllBytes(path, oversized);
        var exception = Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            new TransactionalQuarantineEngine(customVaultDir: Vault));
        Assert.Contains("LegacyMigrationRequired", exception.Message);
        Assert.Equal(oversized, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublishedRestoreRetainsSuccessAndAuditPendingWhenMetadataFails(bool authenticated)
    {
        string source = Fixture("restore-metadata-failure.txt");
        using var engine = new TransactionalQuarantineEngine(customVaultDir: Vault);
        var captured = await engine.ExecuteQuarantineAsync(await Request(source));
        Assert.True(captured.Success, captured.Message);
        var entry = (await engine.GetItemByIdAsync(captured.QuarantineId))!;
        using (var connection = new SqliteConnection("Data Source=" + Path.Combine(Vault, "QuarantineVault.db") + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TRIGGER fail_restored_update BEFORE UPDATE OF Status ON QuarantineEntries " +
                "WHEN NEW.Status = 1 BEGIN SELECT RAISE(ABORT, 'Inert restore metadata failure fixture'); END;";
            command.ExecuteNonQuery();
        }
        string destination = Path.Combine(_root, "restore-published.txt");
        var result = authenticated
            ? await engine.ExecuteRestoreForCallerAsync(entry.Id, entry.OwnerSid!, false,
                async (_, bytes, ct) =>
                {
                    await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    await bytes.CopyToAsync(output, ct);
                }, destination)
            : await engine.ExecuteRestoreAsync(entry.Id, destination);
        Assert.True(result.Success, result.Message);
        Assert.True(result.AuditPending);
        Assert.Equal(destination, result.RestoredPath);
        Assert.Equal("Inert owned fixture data.", await File.ReadAllTextAsync(destination));
        Assert.Equal(QuarantineStatus.Quarantined, (await engine.GetItemByIdAsync(entry.Id))!.Status);
    }

    [Theory]
    [InlineData("oversized-metadata", true)]
    [InlineData("oversized-cipher", true)]
    [InlineData("invalid-digest", false)]
    [InlineData("cipher-size-mismatch", false)]
    public async Task MalformedLegacyV2MetadataEmitsNoPlaintext(string scenario, bool budgetExceeded)
    {
        string path = Path.Combine(_root, "malformed-v2.quar");
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
        using (var writer = new BinaryWriter(file, Encoding.UTF8))
        {
            writer.Write("ULTRON_QUAR_V2"); writer.Write(16); writer.Write(new byte[16]);
            if (scenario == "oversized-metadata") writer.Write7BitEncodedInt(1_000_000);
            else
            {
                writer.Write(new string(scenario == "invalid-digest" ? 'G' : 'A', 64));
                writer.Write(scenario == "oversized-cipher" ? 64 * 1024 * 1024 + 16 : 32);
                writer.Write(new byte[16]);
            }
        }
        using var output = new MemoryStream();
        if (budgetExceeded)
        {
            var exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
                VaultContainerCodec.DecryptVaultStreamAsync(path, output, new byte[32]));
            Assert.Contains("LegacyMigrationRequired", exception.Message);
        }
        else Assert.False(await VaultContainerCodec.DecryptVaultStreamAsync(path, output, new byte[32]));
        Assert.Empty(output.ToArray());
    }

    [Fact]
    public async Task LegacySchemaIsBackedUpBeforeAddingNullableOwnerColumn()
    {
        Directory.CreateDirectory(Vault);
        string databasePath = Path.Combine(Vault, "QuarantineVault.db");
        using (var connection = new SqliteConnection("Data Source=" + databasePath + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = @"CREATE TABLE QuarantineEntries (
                Id INTEGER PRIMARY KEY,OriginalPath TEXT NOT NULL,CanonicalPath TEXT NOT NULL,QuarantinePath TEXT NOT NULL,
                FileName TEXT NOT NULL,SHA256 TEXT NOT NULL,FileSize INTEGER NOT NULL,Reason TEXT NOT NULL,RiskLevel INTEGER NOT NULL,
                QuarantinedAt TEXT NOT NULL,RestoredAt TEXT,Status INTEGER NOT NULL);
                INSERT INTO QuarantineEntries VALUES (1,'old','old','old.quar','old', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,'legacy',0,'2026-01-01T00:00:00Z',NULL,0);";
            command.ExecuteNonQuery();
        }
        using var database = new QuarantineVaultDatabase(Vault);
        Assert.Null((await database.GetEntryByIdAsync(1))!.OwnerSid);
        string snapshotPath = Assert.Single(Directory.GetFiles(Vault, "QuarantineVault.owner-v1.*.backup.db"));
        using var snapshot = new SqliteConnection("Data Source=" + snapshotPath + ";Pooling=False");
        snapshot.Open();
        using var integrity = snapshot.CreateCommand();
        integrity.CommandText = "PRAGMA integrity_check;";
        Assert.Equal("ok", integrity.ExecuteScalar());
        integrity.CommandText = "SELECT COUNT(1) FROM pragma_table_info('QuarantineEntries') WHERE name='OwnerSid';";
        Assert.Equal(0L, Convert.ToInt64(integrity.ExecuteScalar()));
    }

    [Fact]
    public async Task LegacyJsonCannotClaimCallerSuppliedOwner()
    {
        Directory.CreateDirectory(Vault);
        await File.WriteAllTextAsync(Path.Combine(Vault, "quarantine_index.json"), JsonSerializer.Serialize(new[] { Metadata(1, Alice) }));
        using var database = new QuarantineVaultDatabase(Vault);
        Assert.Null((await database.GetEntryByIdAsync(1))!.OwnerSid);
    }

    private string Fixture(string name)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, "Inert owned fixture data.");
        return path;
    }

    private static async Task<QuarantineRequest> Request(string path, string reason = "Inert fixture containment") => new()
    { TargetFilePath = path, ThreatReason = reason, ExpectedSha256 = await new HashService().ComputeSha256Async(path), ForceKillHoldingProcesses = false };

    private QuarantineEntry Metadata(int id, string? owner) => new()
    {
        Id = id, OriginalPath = Path.Combine(_root, "metadata" + id), QuarantinePath = Path.Combine(Vault, "missing" + id + ".quar"),
        FileName = "metadata", SHA256 = new string('A', 64), FileSize = 1, OwnerSid = owner, Status = QuarantineStatus.Quarantined
    };

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string newLinkPath, string existingFilePath, IntPtr securityAttributes);

    /// <summary>Removes only the uniquely created test root and backup siblings created beneath that root.</summary>
    public void Dispose() => Directory.Delete(_root, true);
}
