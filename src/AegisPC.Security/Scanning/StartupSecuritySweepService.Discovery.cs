using AegisPC.Core.Helpers;
using AegisPC.Core.Models;

namespace AegisPC.Security.Scanning;

/// <summary>Streams scoped startup files without extension-based trust, following neither reparse points nor implicit network locations.</summary>
public partial class StartupSecuritySweepService
{
    private ScanCoverageSummary _discoveryCoverage = new();
    private int _discoveredFiles;

    private IEnumerable<FileInfo> EnumerateSweepFiles(IEnumerable<string> targets, CancellationToken token)
        => StartupCandidateScheduling.Order(EnumerateUnorderedSweepFiles(targets, token), token);

    private IEnumerable<FileInfo> EnumerateUnorderedSweepFiles(IEnumerable<string> targets, CancellationToken token)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string target in targets.OrderBy(GetLocationRiskPriority))
        {
            var pending = new Stack<string>();
            pending.Push(Path.GetFullPath(target));
            while (pending.TryPop(out string? path))
            {
                token.ThrowIfCancellationRequested();
                if (!seen.Add(path)) continue;
                if (seen.Count > 100_000)
                {
                    _discoveryCoverage.RecordLimitation("StartupDiscoveryIdentityBudgetExceeded");
                    yield break;
                }
                FileAttributes attributes;
                try { attributes = File.GetAttributes(path); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { _discoveryCoverage.RecordDirectoryError(); continue; }
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                { _discoveryCoverage.RecordReparseSkip(); continue; }
                if (!ImplicitLocalPathPolicy.IsEligible(path))
                { _discoveryCoverage.RecordLimitation("StartupNonLocalTargetNotInspected"); continue; }
                if ((attributes & FileAttributes.Directory) == 0)
                {
                    yield return new FileInfo(path);
                    continue;
                }
                foreach (string entry in SafeEntries(path))
                {
                    token.ThrowIfCancellationRequested();
                    // Enumerate files immediately; postpone directories without buffering file contents.
                    FileAttributes childAttributes;
                    try { childAttributes = File.GetAttributes(entry); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    { _discoveryCoverage.RecordLimitation("StartupEntryUnavailable"); continue; }
                    if ((childAttributes & FileAttributes.ReparsePoint) != 0)
                    { _discoveryCoverage.RecordReparseSkip(); continue; }
                    if (seen.Count + pending.Count >= 100_000)
                    { _discoveryCoverage.RecordLimitation("StartupDiscoveryIdentityBudgetExceeded"); yield break; }
                    if ((childAttributes & FileAttributes.Directory) != 0) pending.Push(entry);
                    else if (seen.Add(entry)) yield return new FileInfo(entry);
                }
            }
        }
    }

    private IEnumerable<string> SafeEntries(string path)
    {
        IEnumerator<string> enumerator;
        try { enumerator = Directory.EnumerateFileSystemEntries(path).GetEnumerator(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { _discoveryCoverage.RecordDirectoryError(); yield break; }
        using (enumerator)
        {
            while (true)
            {
                bool moved;
                try { moved = enumerator.MoveNext(); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { _discoveryCoverage.RecordDirectoryError(); yield break; }
                if (!moved) yield break;
                yield return enumerator.Current;
            }
        }
    }
}
