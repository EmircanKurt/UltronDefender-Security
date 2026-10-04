using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Text.Json.Serialization;

namespace AegisPC.Core.Models;

/// <summary>Separates completion of a scan job from completeness of its inspection coverage.</summary>
public sealed class ScanCoverageSummary
{
    /// <summary>Creates an initially complete summary to which actual gaps may be added.</summary>
    public ScanCoverageSummary() { }
    /// <summary>Restores recorded coverage from persisted reports; getters alone cannot deserialize counters.</summary>
    [JsonConstructor]
    public ScanCoverageSummary(int unreadableDirectories, int unreadableProcesses, int partialArchives,
        int skippedReparsePoints, string[]? limitations)
    {
        _directories = Math.Max(0, unreadableDirectories);
        _processes = Math.Max(0, unreadableProcesses);
        _archives = Math.Max(0, partialArchives);
        _reparsePoints = Math.Max(0, skippedReparsePoints);
        foreach (var reason in (limitations ?? Array.Empty<string>()).Take(129)) RecordLimitation(reason);
    }
    private int _directories, _processes, _archives, _reparsePoints;
    private readonly ConcurrentDictionary<string, byte> _limitations = new(StringComparer.Ordinal);

    /// <summary>Directories that could not be enumerated.</summary>
    public int UnreadableDirectories => Volatile.Read(ref _directories);
    /// <summary>Processes whose image or module list could not be inspected.</summary>
    public int UnreadableProcesses => Volatile.Read(ref _processes);
    /// <summary>Archives for which inspection was only partial.</summary>
    public int PartialArchives => Volatile.Read(ref _archives);
    /// <summary>Reparse points deliberately not followed.</summary>
    public int SkippedReparsePoints => Volatile.Read(ref _reparsePoints);
    /// <summary>Bounded reason codes, not a claim that omitted sources are clean.</summary>
    public string[] Limitations => _limitations.Keys.OrderBy(x => x, StringComparer.Ordinal).ToArray();
    /// <summary>True only when no inspection gap has been recorded.</summary>
    public bool IsComplete => UnreadableDirectories == 0 && UnreadableProcesses == 0 &&
        PartialArchives == 0 && SkippedReparsePoints == 0 && _limitations.IsEmpty;

    /// <summary>Records an enumeration failure without disclosing a private path.</summary>
    public void RecordDirectoryError() => Interlocked.Increment(ref _directories);
    /// <summary>Records a module or process access failure.</summary>
    public void RecordProcessError() => Interlocked.Increment(ref _processes);
    /// <summary>Records an archive inspection gap.</summary>
    public void RecordPartialArchive() => Interlocked.Increment(ref _archives);
    /// <summary>Records an intentionally omitted reparse target.</summary>
    public void RecordReparseSkip() => Interlocked.Increment(ref _reparsePoints);
    /// <summary>Records a bounded, unique inspection limitation.</summary>
    public void RecordLimitation(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason)) return;
        if (_limitations.Count >= 128) { _limitations.TryAdd("AdditionalCoverageLimitations", 0); return; }
        _limitations.TryAdd(reason.Length <= 240 ? reason : reason[..240], 0);
    }
}
