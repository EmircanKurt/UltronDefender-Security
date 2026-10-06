using System;
using System.Collections.Generic;
using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Security.Safety;

/// <summary>Builds process-local exclusion indexes without publishing partially rebuilt or externally mutable rules.</summary>
internal sealed class ExclusionSnapshot
{
    internal static readonly ExclusionSnapshot Empty = new(Array.Empty<ExclusionEntry>(), static path => path);
    internal readonly Dictionary<int, ExclusionEntry> Entries = new();
    internal readonly Dictionary<string, ExclusionEntry> Paths = new(StringComparer.OrdinalIgnoreCase);
    internal readonly Dictionary<string, ExclusionEntry> Folders = new(StringComparer.OrdinalIgnoreCase);
    internal readonly Dictionary<string, ExclusionEntry> Hashes = new(StringComparer.OrdinalIgnoreCase);

    internal ExclusionSnapshot(IEnumerable<ExclusionEntry> entries, Func<string, string> normalizePath)
    {
        foreach (var original in entries)
        {
            var entry = CopyEntry(original);
            Entries[entry.Id] = entry;
            if (entry.Type == ExclusionType.Sha256)
            {
                Hashes[entry.Value] = entry;
                continue;
            }
            string path = normalizePath(entry.Value);
            Paths[path] = entry;
            if (entry.IncludeSubdirectories || Directory.Exists(path))
            {
                // Multiple persisted rules may have different recursion settings; retain their combined coverage.
                if (!Folders.TryGetValue(path, out var prior) || !prior.IncludeSubdirectories)
                    Folders[path] = entry;
            }
        }
    }

    internal static ExclusionEntry CopyEntry(ExclusionEntry entry) => new()
    {
        Id = entry.Id, Type = entry.Type, Value = entry.Value, AddedUtc = entry.AddedUtc,
        Reason = entry.Reason, IncludeSubdirectories = entry.IncludeSubdirectories
    };
}
