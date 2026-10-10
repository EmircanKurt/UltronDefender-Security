namespace AegisPC.Security.Scanning;

/// <summary>Orders bounded metadata windows for early progress without omitting any file or declaring content trusted.</summary>
public static class StartupCandidateScheduling
{
    /// <summary>Prioritizes smaller files within each finite window; unknown sizes remain inspectable and every window drains.</summary>
    public static IEnumerable<FileInfo> Order(IEnumerable<FileInfo> candidates, CancellationToken token, int windowSize = 64)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        if (windowSize is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(windowSize));
        using var source = candidates.GetEnumerator();
        var window = new List<(FileInfo File, long Size)>(windowSize);
        while (true)
        {
            window.Clear();
            while (window.Count < windowSize)
            {
                token.ThrowIfCancellationRequested();
                if (!source.MoveNext()) break;
                FileInfo file = source.Current;
                long size;
                try { size = file.Length; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    System.Diagnostics.Trace.TraceWarning("Startup candidate size unavailable ({0}); candidate retained for inspection.", ex.GetType().Name);
                    size = long.MaxValue;
                }
                window.Add((file, size));
            }
            if (window.Count == 0) yield break;
            foreach (var candidate in window.OrderBy(item => item.Size))
            {
                token.ThrowIfCancellationRequested();
                yield return candidate.File;
            }
        }
    }
}
