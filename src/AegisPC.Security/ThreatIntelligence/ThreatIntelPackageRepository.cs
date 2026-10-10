using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace AegisPC.Security.ThreatIntelligence;

/// <summary>Local signed content and its independent manifest.</summary>
public sealed record SignedIntelPackage(ThreatIntelManifest Manifest, byte[] Content);

/// <summary>
/// Atomic offline package journal with previous-good rollback and a retained sequence high-water mark.
/// Production directory ownership/ACL and multi-user service integration require the Windows VM pilot.
/// This component is not an IPC endpoint and does not fetch data or enable automatic actions.
/// </summary>
public sealed class ThreatIntelPackageRepository
{
    private const int MaxJournalBytes = 24 * 1024 * 1024;
    private readonly string _root;
    private readonly SignedThreatIntelStore _store;
    private readonly object _gate = new();
    private Journal? _current;
    private sealed record Journal(SignedIntelPackage Active, SignedIntelPackage? Previous);

    /// <summary>Uses a caller-protected offline directory; production ACL setup is outside this component.</summary>
    public ThreatIntelPackageRepository(string directory, SignedThreatIntelStore store)
    {
        _root = Path.GetFullPath(directory);
        _store = store;
    }

    /// <summary>Authenticates journal history at startup; expired entries retain replay state but cannot be used for detection.</summary>
    public ThreatIntelInstallResult Load()
    {
        lock (_gate)
        {
            try
            {
                using var lease = AcquireLease();
                return LoadHeld();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            { return new(false, "JournalUnavailable"); }
        }
    }

    /// <summary>Single-writer file lease plus atomic replace; cancelled/failed transfer never replaces the active package.</summary>
    public ThreatIntelInstallResult Install(SignedIntelPackage package)
    {
        lock (_gate)
        {
            if (package.Content == null || package.Content.Length > SignedThreatIntelStore.MaxContentBytes)
                return new(false, "ContentTooLarge");
            package = new(package.Manifest, (byte[])package.Content.Clone());
            try
            {
                using var lease = AcquireLease();
                if (File.Exists(Path.Combine(_root, "intel-state.json")))
                {
                    var loaded = LoadHeld();
                    if (!loaded.Accepted) return loaded;
                }
                var next = new Journal(package, _current?.Active);
                var result = _store.Install(package.Manifest, package.Content, () => Persist(next));
                if (result.Accepted) _current = next;
                return result;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            { return new(false, "JournalUnavailable"); }
        }
    }

    /// <summary>Only the previously verified package can be restored. The highest signed sequence remains in the journal.</summary>
    public ThreatIntelInstallResult Rollback()
    {
        lock (_gate)
        {
            try
            {
                using var lease = AcquireLease();
                var loaded = LoadHeld();
                if (!loaded.Accepted) return loaded;
                if (_current?.Previous == null) return new(false, "NoPreviousPackage");
                var previous = _current.Previous;
                var next = new Journal(previous, _current.Active);
                var result = _store.Install(previous.Manifest, previous.Content, () => Persist(next), rollback: true);
                if (result.Accepted) _current = next;
                return result;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            { return new(false, "JournalUnavailable"); }
        }
    }

    private FileStream AcquireLease()
    {
        Directory.CreateDirectory(_root);
        if ((File.GetAttributes(_root) & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse root rejected.");
        return new FileStream(Path.Combine(_root, "intel.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    private ThreatIntelInstallResult LoadHeld()
    {
        string path = Path.Combine(_root, "intel-state.json");
        if (!File.Exists(path)) return new(false, "JournalMissing");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > MaxJournalBytes) return new(false, "JournalTooLarge");
        var journal = JsonSerializer.Deserialize<Journal>(stream, new JsonSerializerOptions { MaxDepth = 12 });
        if (journal?.Active?.Content == null || journal.Active.Manifest == null) return new(false, "JournalInvalid");
        // VerifyJournal validates both packages before changing the store snapshot.
        var verification = _store.VerifyJournal(journal.Active, journal.Previous);
        if (!verification.Accepted) return verification;
        _current = journal;
        return verification;
    }

    private void Persist(Journal journal)
    {
        string staging = Path.Combine(_root, "intel-staging-" + Guid.NewGuid().ToString("N"));
        string active = Path.Combine(_root, "intel-state.json");
        try
        {
            using (var stream = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream, journal);
                if (stream.Length > MaxJournalBytes) throw new IOException("Journal size limit exceeded.");
                stream.Flush(flushToDisk: true);
            }
            if (File.Exists(active)) File.Replace(staging, active, Path.Combine(_root, "intel-state.backup.json"));
            else File.Move(staging, active);
        }
        finally { if (File.Exists(staging)) File.Delete(staging); }
    }
}
