using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using AegisPC.Contracts.ThreatIntelligence;

namespace AegisPC.Security.ThreatIntelligence;

/// <summary>Separate intelligence signature contract; it cannot authorize application updates.</summary>
public sealed record ThreatIntelManifest(int Schema, string Product, long Sequence, string Version,
    DateTimeOffset IssuedAtUtc, DateTimeOffset ExpiresAtUtc, int RecordCount, int ContentBytes,
    string ContentSha256, bool RedistributionReviewed, string SignatureBase64);

/// <summary>Source metadata. Family/name is descriptive, never a rule or a probability.</summary>
public sealed record ThreatIntelPackageEntry(string Sha256, string Name, string Category, int Severity,
    string Source, string SourceReference, DateTimeOffset AcquiredAtUtc);

/// <summary>Validation outcome; rejected packages leave the previous snapshot untouched.</summary>
public sealed record ThreatIntelInstallResult(bool Accepted, string Code, int Records = 0);

/// <summary>
/// Bounded, local RSA-PSS/SHA-256 verifier with immutable snapshots. Caller-supplied records and
/// source strings cannot activate hashes. The key is pinned by the composition root, not a manifest.
/// Public instances support isolated tooling/tests; production uses a separate pinned catalogue.
/// </summary>
public sealed class SignedThreatIntelStore
{
    /// <summary>Maximum signed content size before copying or parsing untrusted bytes.</summary>
    public const int MaxContentBytes = 8 * 1024 * 1024;
    /// <summary>Maximum unique SHA-256 records in one verified snapshot.</summary>
    public const int MaxRecords = 25000;
    private readonly string _publicKeyPem;
    private readonly object _gate = new();
    private Dictionary<string, ThreatIntelPackageEntry> _active = new(StringComparer.OrdinalIgnoreCase);
    private ThreatIntelManifest? _manifest;
    private long _highestSequence;
    /// <summary>Active records only; expired packages expose zero usable signatures.</summary>
    public int Count { get { lock (_gate) return IsCurrent(DateTimeOffset.UtcNow) ? _active.Count : 0; } }
    /// <summary>Largest authenticated sequence observed, retained even during rollback or expiry.</summary>
    public long HighestSequence { get { lock (_gate) return _highestSequence; } }

    /// <summary>Pins a composition-root public key; an empty key leaves package activation closed.</summary>
    public SignedThreatIntelStore(string publicKeyPem) => _publicKeyPem = publicKeyPem;

    /// <summary>Returns a detached verified record. An expired package fails closed, never silently clean.</summary>
    public bool TryGet(string sha256, out ThreatIntelRecord? record)
    {
        record = null;
        if (!Sha256Identity.IsValid(sha256)) return false;
        lock (_gate)
        {
            if (!IsCurrent(DateTimeOffset.UtcNow) || !_active.TryGetValue(sha256, out var entry)) return false;
            record = new ThreatIntelRecord { Sha256 = entry.Sha256, ThreatName = entry.Name,
                Category = entry.Category, Severity = entry.Severity, Source = entry.Source,
                SourceReference = entry.SourceReference, TimestampUtc = entry.AcquiredAtUtc.UtcDateTime,
                PackageVersion = _manifest!.Version, Verification = ThreatIntelVerification.SignedPackage,
                ValidUntilUtc = _manifest.ExpiresAtUtc.UtcDateTime };
            return true;
        }
    }

    /// <summary>
    /// Verifies all metadata/content before activation. Persistence must complete inside commit
    /// before a new snapshot is published. Rollback keeps the high-water mark to reject replay.
    /// </summary>
    public ThreatIntelInstallResult Install(ThreatIntelManifest manifest, ReadOnlyMemory<byte> content,
        Action? commit = null, bool rollback = false, DateTimeOffset? nowUtc = null)
    {
        lock (_gate)
        {
            if (content.Length > MaxContentBytes) return new(false, "ContentTooLarge");
            content = content.ToArray(); // Capture the bytes once; caller mutation cannot change verified content.
            DateTimeOffset now = nowUtc ?? DateTimeOffset.UtcNow;
            var check = Validate(manifest, content, now, out var entries);
            if (!check.Accepted) return check;
            if ((!rollback && manifest.Sequence <= _highestSequence) ||
                (rollback && (manifest.Sequence > _highestSequence || _highestSequence == 0)))
                return new(false, "ReplayRejected");
            try { commit?.Invoke(); }
            catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
            { return new(false, "PersistenceFailed"); }
            _active = entries!;
            _manifest = manifest;
            _highestSequence = Math.Max(_highestSequence, manifest.Sequence);
            return check;
        }
    }

    internal ThreatIntelInstallResult VerifyJournal(SignedIntelPackage active, SignedIntelPackage? previous)
    {
        lock (_gate)
        {
            // Expired authenticated history must preserve replay protection without blocking a
            // future update. Count/TryGet independently reject use of the expired active snapshot.
            var check = Validate(active.Manifest, active.Content, DateTimeOffset.UtcNow, out var entries, requireCurrent: false);
            if (!check.Accepted) return check;
            long highest = active.Manifest.Sequence;
            if (previous != null)
            {
                var prior = Validate(previous.Manifest, previous.Content, DateTimeOffset.UtcNow, out _, requireCurrent: false);
                if (!prior.Accepted) return new(false, "PreviousPackageInvalid");
                highest = Math.Max(highest, previous.Manifest.Sequence);
            }
            if (highest < _highestSequence) return new(false, "JournalReplayRejected");
            _active = entries!; _manifest = active.Manifest; _highestSequence = highest;
            return check;
        }
    }

    /// <summary>Canonical signed payload. Signature binds exact content bytes, size, expiry, version and sequence.</summary>
    public static byte[] SigningPayload(ThreatIntelManifest m) => JsonSerializer.SerializeToUtf8Bytes(new object[]
    {
        m.Schema, m.Product, m.Sequence, m.Version, m.IssuedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
        m.ExpiresAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture), m.RecordCount,
        m.ContentBytes, m.ContentSha256.ToUpperInvariant(), m.RedistributionReviewed
    });

    private ThreatIntelInstallResult Validate(ThreatIntelManifest m, ReadOnlyMemory<byte> content,
        DateTimeOffset now, out Dictionary<string, ThreatIntelPackageEntry>? entries, bool requireCurrent = true)
    {
        entries = null;
        if (string.IsNullOrWhiteSpace(_publicKeyPem)) return new(false, "PublisherKeyNotProvisioned");
        if (m.Schema != 1 || m.Product != "Ultron.ThreatIntel" || m.Sequence <= 0 ||
            string.IsNullOrWhiteSpace(m.Version) || m.Version.Length > 80 || !m.RedistributionReviewed ||
            m.RecordCount is < 1 or > MaxRecords || m.ContentBytes is < 1 or > MaxContentBytes ||
            content.Length != m.ContentBytes || !Sha256Identity.IsValid(m.ContentSha256)) return new(false, "ManifestInvalid");
        if ((requireCurrent && m.ExpiresAtUtc <= now) || m.IssuedAtUtc > now.AddMinutes(5) ||
            m.ExpiresAtUtc <= m.IssuedAtUtc || m.ExpiresAtUtc - m.IssuedAtUtc > TimeSpan.FromDays(30))
            return new(false, "ValidityRejected");
        if (!string.Equals(Convert.ToHexString(SHA256.HashData(content.Span)), m.ContentSha256,
            StringComparison.OrdinalIgnoreCase)) return new(false, "ContentHashMismatch");
        try
        {
            if (m.SignatureBase64 is not { Length: > 0 and <= 2048 }) return new(false, "SignatureInvalid");
            using var rsa = RSA.Create();
            rsa.ImportFromPem(_publicKeyPem);
            if (rsa.KeySize < 3072 || !rsa.VerifyData(SigningPayload(m), Convert.FromBase64String(m.SignatureBase64),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) return new(false, "SignatureInvalid");
            using var shape = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 8 });
            if (shape.RootElement.ValueKind != JsonValueKind.Array || shape.RootElement.GetArrayLength() != m.RecordCount)
                return new(false, "RecordCountMismatch");
            var records = JsonSerializer.Deserialize<ThreatIntelPackageEntry[]>(content.Span,
                new JsonSerializerOptions { MaxDepth = 8 });
            if (records == null || records.Length != m.RecordCount) return new(false, "RecordCountMismatch");
            var pending = new Dictionary<string, ThreatIntelPackageEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in records)
            {
                if (entry == null || !ValidEntry(entry, m, now) ||
                    !pending.TryAdd(entry.Sha256.ToUpperInvariant(), entry)) return new(false, "RecordInvalid");
            }
            entries = pending;
            return new(true, "Verified", entries.Count);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or JsonException)
        { return new(false, "PackageInvalid"); }
    }

    private static bool ValidEntry(ThreatIntelPackageEntry e, ThreatIntelManifest m, DateTimeOffset now) =>
        Sha256Identity.IsValid(e.Sha256) && e.Name is { Length: > 0 and <= 256 } &&
        e.Category is { Length: > 0 and <= 80 } && e.Severity is >= 1 and <= 100 &&
        e.Source is { Length: > 0 and <= 80 } && e.SourceReference is { Length: > 0 and <= 2048 } &&
        Uri.TryCreate(e.SourceReference, UriKind.Absolute, out var uri) && uri.Scheme == "https" &&
        string.IsNullOrEmpty(uri.UserInfo) && e.AcquiredAtUtc > DateTimeOffset.UnixEpoch &&
        e.AcquiredAtUtc <= now.AddMinutes(5) && e.AcquiredAtUtc <= m.IssuedAtUtc.AddMinutes(5);

    private bool IsCurrent(DateTimeOffset now) => _manifest != null && _manifest.ExpiresAtUtc > now && _manifest.IssuedAtUtc <= now.AddMinutes(5);
}
