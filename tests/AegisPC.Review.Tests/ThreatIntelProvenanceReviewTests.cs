using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Text.Json;
using AegisPC.Contracts.ThreatIntelligence;
using AegisPC.Security.Scanning;
using AegisPC.Security.ThreatIntelligence;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Inert metadata only. Runtime-generated lab signing key is not a deployment trust anchor.</summary>
[Collection("SequentialDiskTests")]
public sealed class ThreatIntelProvenanceReviewTests
{
    private const string Hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static readonly RSAParameters Key = GenerateKey();
    private static RSAParameters GenerateKey() { using var rsa = RSA.Create(3072); return rsa.ExportParameters(true); }
    private static RSA Signer() { var rsa = RSA.Create(); rsa.ImportParameters(Key); return rsa; }
    private static SignedThreatIntelStore Store() { using var rsa = Signer(); return new(rsa.ExportSubjectPublicKeyInfoPem()); }
    private static SignedIntelPackage Package(long sequence, string hash = Hash)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new[] { new ThreatIntelPackageEntry(hash,
            "Inert lab fixture", "Lab", 80, "LabMetadata", "https://example.org/inert-metadata", DateTimeOffset.UtcNow) });
        var m = new ThreatIntelManifest(1, "Ultron.ThreatIntel", sequence, $"lab-{sequence}",
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1), 1, bytes.Length,
            Convert.ToHexString(SHA256.HashData(bytes)), true, "");
        using var rsa = Signer();
        m = m with { SignatureBase64 = Convert.ToBase64String(rsa.SignData(SignedThreatIntelStore.SigningPayload(m),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) };
        return new(m, bytes);
    }

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("44D88612FEA8A8F36DE82E1278ABB02F")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ")]
    [InlineData("ＧAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void InvalidSha256CannotEnterDetection(string? hash) => Assert.False(Sha256Identity.IsValid(hash));

    [Fact]
    public void UnprovenSeedsAndCallerLabelsCannotAuthorizeExactDetection()
    {
        var store = new ThreatIntelligenceStore();
        store.RegisterMaliciousHash(Hash, "Inert", "Malware", 100);
        Assert.True(store.TryGetUnverifiedRecord(Hash, out var legacy));
        Assert.False(legacy!.IsAuthoritative);
        Assert.False(store.IsMaliciousHash(Hash, out _));
        Assert.False(store.IsMaliciousHash("ED01EB844542A16B02D23B9E95B3DE1B2C876EEA88BF61E7E9D373B15154E9EC", out _));
        Assert.False(MalwareSignatureDatabase.CheckHash("ED01EB844542A16B02D23B9E95B3DE1B2C876EEA88BF61E7E9D373B15154E9EC").IsMatched);
        Assert.False(store.IsTrustedPublisher("Fake Microsoft Corporation"));
        Assert.False(store.IsTrustedPublisher("Microsoft Corporation"));
        store.RegisterTrustedHash(Hash);
        Assert.False(store.IsTrustedHash(Hash));
    }

    [Fact]
    public void EicarIsClearlySeparatedAndDetached()
    {
        const string testHash = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
        Assert.True(AuthoritativeThreatCatalog.TryGet(testHash, out var record));
        Assert.Equal(ThreatIntelVerification.BuiltInTestMarker, record!.Verification);
        Assert.Equal("TestMalware", record.Category);
        record.Category = "Ransomware";
        Assert.True(AuthoritativeThreatCatalog.TryGet(testHash, out var again));
        Assert.Equal("TestMalware", again!.Category);
    }

    [Fact]
    public void ValidSignaturePublishesDetachedRecordsAndRejectsReplay()
    {
        var store = Store(); var p = Package(1);
        Assert.True(store.Install(p.Manifest, p.Content).Accepted);
        Assert.True(store.TryGet(Hash, out var record));
        Assert.Equal(ThreatIntelVerification.SignedPackage, record!.Verification);
        Assert.Equal("lab-1", record.PackageVersion);
        record.Verification = ThreatIntelVerification.Unverified;
        Assert.True(store.TryGet(Hash, out var again));
        Assert.True(again!.IsAuthoritative);
        Assert.Equal("ReplayRejected", store.Install(p.Manifest, p.Content).Code);
    }

    [Fact]
    public void InvalidHashSignatureAndValidityNeverReplacePreviousGood()
    {
        var store = Store(); var first = Package(1); var second = Package(2);
        Assert.True(store.Install(first.Manifest, first.Content).Accepted);
        Assert.False(store.Install(second.Manifest with { SignatureBase64 = "AAAA" }, second.Content).Accepted);
        var changed = (byte[])second.Content.Clone(); changed[0] ^= 1;
        Assert.Equal("ContentHashMismatch", store.Install(second.Manifest, changed).Code);
        Assert.Equal("ValidityRejected", store.Install(second.Manifest with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1) }, second.Content).Code);
        Assert.True(store.TryGet(Hash, out var record)); Assert.Equal("lab-1", record!.PackageVersion);
    }

    [Fact]
    public void MissingKeyOversizedTransferAndFailedCommitCannotActivate()
    {
        var p = Package(1);
        Assert.Equal("PublisherKeyNotProvisioned", new SignedThreatIntelStore("").Install(p.Manifest, p.Content).Code);
        var store = Store();
        Assert.Equal("ContentTooLarge", store.Install(p.Manifest, new byte[SignedThreatIntelStore.MaxContentBytes + 1]).Code);
        Assert.Equal("PersistenceFailed", store.Install(p.Manifest, p.Content, () => throw new IOException("inert fault")).Code);
        Assert.Equal(0, store.Count); Assert.Equal(0, store.HighestSequence);
    }

    [Fact]
    public void AtomicRepositoryRollbackRetainsReplayFloorAcrossRestart()
    {
        string root = Path.Combine(Path.GetTempPath(), "UltronIntelLab-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = Store(); var repo = new ThreatIntelPackageRepository(root, store);
            Assert.True(repo.Install(Package(1)).Accepted);
            Assert.True(repo.Install(Package(2)).Accepted);
            Assert.True(repo.Rollback().Accepted);
            Assert.True(store.TryGet(Hash, out var record)); Assert.Equal("lab-1", record!.PackageVersion);
            var restarted = Store(); var reload = new ThreatIntelPackageRepository(root, restarted);
            Assert.True(reload.Load().Accepted);
            Assert.Equal(2, restarted.HighestSequence);
            Assert.Equal("ReplayRejected", reload.Install(Package(2)).Code);
            Assert.True(reload.Install(Package(3)).Accepted);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public void SignedMalformedRecordCannotBecomeVerified()
    {
        var p = Package(1, new string('Z', 64));
        Assert.Equal("RecordInvalid", Store().Install(p.Manifest, p.Content).Code);
    }

    [Fact]
    public void LegacyDatabaseMigrationKeepsBackupAndUnsignedRowsReviewOnly()
    {
        string root = Path.Combine(Path.GetTempPath(), "UltronIntelMigration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string path = Path.Combine(root, "legacy.db");
        try
        {
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Pooling=False"))
            {
                connection.Open(); using var sql = connection.CreateCommand();
                sql.CommandText = "CREATE TABLE ThreatSignatures (Sha256 TEXT PRIMARY KEY COLLATE NOCASE, Name TEXT NOT NULL, Category TEXT NOT NULL, Severity INTEGER NOT NULL, Source TEXT NOT NULL, AddedUtc TEXT NOT NULL); INSERT INTO ThreatSignatures VALUES ($hash, 'Inert legacy', 'Lab', 100, 'MalwareBazaar', '2020-01-01');";
                sql.Parameters.AddWithValue("$hash", Hash); sql.ExecuteNonQuery();
            }
            ThreatSignatureDatabase.ResetForTesting(path);
            Assert.False(ThreatSignatureDatabase.CheckHash(Hash).IsMatched);
            Assert.True(ThreatSignatureDatabase.TryGetUnverifiedMetadata(Hash, out _));
            Assert.Single(Directory.GetFiles(root, "legacy.db.backup-*"));
            using var migrated = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Mode=ReadOnly;Pooling=False");
            migrated.Open(); using var query = migrated.CreateCommand();
            query.CommandText = "SELECT VerificationStatus FROM ThreatSignatures WHERE Sha256=$hash";
            query.Parameters.AddWithValue("$hash", Hash);
            Assert.Equal("Unverified", query.ExecuteScalar());
            Assert.Equal(0, ThreatSignatureDatabase.ImportThreatHashes(new[]
                { (new string('Z', 64), "Invalid", "Lab", 100, "MalwareBazaar") }));
        }
        finally { ThreatSignatureDatabase.ResetForTesting(); Directory.Delete(root, true); }
    }

    [Fact]
    public void TamperedJournalCannotReplacePreviouslyVerifiedSnapshot()
    {
        string root = Path.Combine(Path.GetTempPath(), "UltronIntelTamper-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = Store(); var repo = new ThreatIntelPackageRepository(root, store);
            Assert.True(repo.Install(Package(1)).Accepted);
            File.WriteAllText(Path.Combine(root, "intel-state.json"), "{broken transfer");
            Assert.False(repo.Load().Accepted);
            Assert.True(store.TryGet(Hash, out var old)); Assert.Equal("lab-1", old!.PackageVersion);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExpiredJournalHistoryCannotDetectOrBlockFreshUpdate(bool activeExpired)
    {
        string root = Path.Combine(Path.GetTempPath(), "UltronIntelExpiry-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            DateTimeOffset past = DateTimeOffset.UtcNow.AddDays(-2);
            byte[] content = JsonSerializer.SerializeToUtf8Bytes(new[] { new ThreatIntelPackageEntry(Hash,
                "Expired inert fixture", "Lab", 80, "LabMetadata", "https://example.org/inert-metadata", past) });
            var manifest = new ThreatIntelManifest(1, "Ultron.ThreatIntel", 1, "expired-lab-1", past,
                past.AddDays(1), 1, content.Length, Convert.ToHexString(SHA256.HashData(content)), true, "");
            using var rsa = Signer();
            manifest = manifest with { SignatureBase64 = Convert.ToBase64String(rsa.SignData(
                SignedThreatIntelStore.SigningPayload(manifest), HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) };
            var expired = new SignedIntelPackage(manifest, content);
            var active = activeExpired ? expired : Package(2);
            File.WriteAllBytes(Path.Combine(root, "intel-state.json"), JsonSerializer.SerializeToUtf8Bytes(
                new { Active = active, Previous = activeExpired ? null : expired }));
            var store = Store(); var repo = new ThreatIntelPackageRepository(root, store);
            Assert.True(repo.Load().Accepted);
            Assert.Equal(activeExpired ? 1 : 2, store.HighestSequence);
            Assert.Equal(!activeExpired, store.TryGet(Hash, out _));
            if (!activeExpired) Assert.Equal("ValidityRejected", repo.Rollback().Code);
            Assert.True(repo.Install(Package(3)).Accepted);
            Assert.True(store.TryGet(Hash, out var fresh));
            Assert.Equal("lab-3", fresh!.PackageVersion);
        }
        finally { Directory.Delete(root, true); }
    }
}
