using System.IO;
using System.Security.Cryptography;
using AegisPC.Contracts.Detection;
using AegisPC.Contracts.Services;
using AegisPC.Contracts.ThreatIntelligence;
using AegisPC.Core.Enums;
using AegisPC.Core.Helpers;
using AegisPC.Core.Models;
using AegisPC.Security.Detection;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;

namespace AegisPC.Tests;

/// <summary>
/// Owns one explicitly supplied, new temporary root. This is a test path guard, not an OS sandbox.
/// The factory exposes inspection only: it has no action adapter, watcher, ETW session, native AMSI,
/// reputation client or installed vault. Synthetic signatures/intelligence are inert and in memory.
/// </summary>
internal sealed class ReviewStageOneFixture : IDisposable
{
    internal const string DirectoryPrefix = "UltronReviewStageOne_";
    private static readonly HashSet<string> DeviceNames = new(
        new[] { "CON", "PRN", "AUX", "NUL" }.Concat(Enumerable.Range(1, 9).SelectMany(index => new[] { "COM" + index, "LPT" + index })),
        StringComparer.OrdinalIgnoreCase);
    private bool _disposed;
    internal string Root { get; }
    internal string InputDirectory => EnsureContainedPath(Path.Combine(Root, "input"));
    internal string RulesDirectory => EnsureContainedPath(Path.Combine(Root, "rules"));
    internal string SettingsPath => EnsureContainedPath(Path.Combine(Root, "state", "settings.json"));
    internal string DatabasePath => EnsureContainedPath(Path.Combine(Root, "state", "review.db"));
    internal string ReportsPath => EnsureContainedPath(Path.Combine(Root, "reports", "history.json"));
    internal string CacheDirectory => EnsureContainedPath(Path.Combine(Root, "cache"));
    internal string VaultDirectory => EnsureContainedPath(Path.Combine(Root, "inert-vault"));
    internal IHashService HashService { get; }
    internal ISignatureVerifier SignatureVerifier { get; }

    /// <summary>Rejects ambient product directories, reused roots and reparse ancestors before any write.</summary>
    internal ReviewStageOneFixture(string temporaryRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(temporaryRoot);
        Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(temporaryRoot));
        string temporaryParent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        if (!ImplicitLocalPathPolicy.HasLocalSyntax(Root) ||
            !Root.StartsWith(temporaryParent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(Root).StartsWith(DirectoryPrefix, StringComparison.Ordinal) ||
            !ImplicitLocalPathPolicy.IsEligible(Root) ||
            Directory.Exists(Root) || File.Exists(Root))
            throw new ArgumentException("Review storage must be a new, uniquely named root below the temporary directory.", nameof(temporaryRoot));
        RejectReparseAncestors(Root);
        Directory.CreateDirectory(Root);
        HashService = new ScopedHashService(this);
        SignatureVerifier = new InertSignatureVerifier(this);
        Directory.CreateDirectory(InputDirectory);
    }

    internal static ReviewStageOneFixture Create() => new(Path.Combine(Path.GetTempPath(), DirectoryPrefix + Guid.NewGuid().ToString("N")));

    /// <summary>Rejects escape, sibling-prefix, alternate stream and reparse routes within this fixture.</summary>
    internal string EnsureContainedPath(string candidate)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidate);
        string full = Path.GetFullPath(candidate);
        if (!full.Equals(Root, StringComparison.OrdinalIgnoreCase) &&
            !full.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("A review fixture path must remain inside its owned temporary root.");
        string relative = Path.GetRelativePath(Root, full);
        if (relative.Contains(':') || relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(component => component != "." && (component.EndsWith('.') || component.EndsWith(' ') || DeviceNames.Contains(component.Split('.')[0]))))
            throw new InvalidOperationException("Alternate streams and ambiguous Windows path components are not review fixtures.");
        RejectReparseAncestors(full);
        return full;
    }

    internal string WriteInput(string relativeName, byte[] bytes)
    {
        string path = EnsureContainedPath(Path.Combine(InputDirectory, relativeName));
        if (!path.StartsWith(InputDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixture input must remain in the input directory.");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>Rejects remote/reparse inputs before any existence check, hash or copy.</summary>
    internal static string RequireLocalInput(string sourcePath)
    {
        string source = Path.GetFullPath(sourcePath);
        if (!ImplicitLocalPathPolicy.HasLocalSyntax(source) || !ImplicitLocalPathPolicy.IsEligible(source))
            throw new InvalidOperationException("Only explicitly selected local benign inputs are accepted by the review fixture.");
        RejectReparseAncestors(source);
        return source;
    }

    /// <summary>Copies an explicitly supplied benign fixture for analysis; production/user originals are read only.</summary>
    internal string ImportReadOnlyInput(string sourcePath, string name)
    {
        string source = RequireLocalInput(sourcePath);
        string target = EnsureContainedPath(Path.Combine(InputDirectory, name));
        if (!target.StartsWith(InputDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Imported input must remain in the input directory.");
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.Copy(source, target, overwrite: false);
        return target;
    }

    /// <summary>
    /// Builds the actual shared detector hub with explicit local rule storage. The optional verifier is
    /// explicit for pre-existing signed-file probes; ordinary smoke tests use the inert unsigned adapter.
    /// No deployed rules are read or written and no physical antivirus test marker is generated.
    /// </summary>
    internal IDetectionHub CreateHub(ISignatureVerifier? signatureVerifier = null)
    {
        Directory.CreateDirectory(RulesDirectory);
        foreach (string name in new[] { "eicar.yar", "mimikatz.yar", "cobaltstrike.yar" })
        {
            string target = EnsureContainedPath(Path.Combine(RulesDirectory, name));
            if (!File.Exists(target))
                File.WriteAllText(target, "rule ReviewInert_" + Path.GetFileNameWithoutExtension(name) + " { condition: false }");
        }
        var yara = new YaraEngine(customRulesDir: RulesDirectory);
        if (!EnsureContainedPath(yara.RulesDirectory).Equals(RulesDirectory, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Review rules escaped the fixture root.");
        var hub = DetectionHubFactory.CreateDefault(hashService: HashService,
            signatureVerifier: signatureVerifier ?? SignatureVerifier, yaraEngine: yara,
            threatStore: new InertThreatStore(), amsiScanService: null);
        return new ScopedInspectionHub(this, hub);
    }

    internal async Task<string> ComputeInputIdentityAsync(string path, CancellationToken ct = default)
    {
        string guarded = EnsureContainedPath(path);
        await using var stream = new FileStream(guarded, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
    }

    private static void RejectReparseAncestors(string path)
    {
        string? current = path;
        while (current != null)
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Reparse points are not accepted by the review fixture.");
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            current = Path.GetDirectoryName(current);
        }
    }

    /// <summary>Deletes only the owned root after checking all children without traversing reparse points.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        EnsureContainedPath(Root);
        var directories = new Queue<string>();
        directories.Enqueue(Root);
        while (directories.TryDequeue(out string? directory))
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory))
            {
                EnsureContainedPath(entry);
                if (Directory.Exists(entry)) directories.Enqueue(entry);
            }
        Directory.Delete(Root, recursive: true);
        _disposed = true;
    }

    private sealed class InertSignatureVerifier(ReviewStageOneFixture fixture) : ISignatureVerifier
    {
        public Task<SignatureInfo> VerifySignatureAsync(string path, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.EnsureContainedPath(path);
            return Task.FromResult(new SignatureInfo { VerificationStatus = SignatureVerificationStatus.Unsigned });
        }
    }

    private sealed class ScopedHashService(ReviewStageOneFixture fixture) : IHashService
    {
        private readonly HashService _actual = new();
        public Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken = default) =>
            _actual.ComputeSha256Async(fixture.EnsureContainedPath(path), cancellationToken);
        public Task<string> ComputeSha1Async(string path, CancellationToken cancellationToken = default) =>
            _actual.ComputeSha1Async(fixture.EnsureContainedPath(path), cancellationToken);
    }

    private sealed class ScopedInspectionHub(ReviewStageOneFixture fixture, IDetectionHub actual) : IDetectionHub
    {
        public IReadOnlyList<IDetectorPlugin> RegisteredDetectors => actual.RegisteredDetectors;
        public void RegisterDetector(IDetectorPlugin detector) => throw new InvalidOperationException("The safe review detector set is immutable.");
        public bool UnregisterDetector(string detectorId) => throw new InvalidOperationException("The safe review detector set is immutable.");
        public Task<DetectionResult> EvaluateAsync(DetectionContext context, CancellationToken cancellationToken = default)
        {
            string guarded = fixture.EnsureContainedPath(context.FilePath);
            if (context.SharedScan != null && !fixture.EnsureContainedPath(context.SharedScan.FilePath).Equals(guarded, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Shared scan identity differs from the guarded input.");
            if (context.ProcessId is > 0 || context.IsRunningProcess)
                throw new InvalidOperationException("Safe fixture inspection does not accept live process context.");
            return actual.EvaluateAsync(context, cancellationToken);
        }
    }

    private sealed class InertThreatStore : IThreatIntelligenceStore
    {
        public int MaliciousSignaturesCount => 0;
        public int TrustedHashesCount => 0;
        public bool IsMaliciousHash(string sha256, out ThreatIntelRecord? record) { record = null; return false; }
        public bool IsTrustedHash(string sha256) => false;
        public bool IsTrustedPublisher(string? publisher) => false;
        public void RegisterMaliciousHash(string sha256, string threatName, string category = "Malware", int severity = 100) =>
            throw new InvalidOperationException("Synthetic review intelligence is immutable.");
        public void RegisterTrustedHash(string sha256) => throw new InvalidOperationException("Synthetic review intelligence is immutable.");
    }
}
