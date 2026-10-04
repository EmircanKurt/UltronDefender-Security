using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Security.RealTime;

/// <summary>Streaming depth-first inspection with a live continuation cursor, not an all-files list.</summary>
internal static class BoundedDirectoryInspection
{
    internal static async Task<bool> WalkAsync(string root, Func<string, CancellationToken, Task> inspect,
        Action<string> gap, CancellationToken cancellationToken)
    {
        var cursors = new Stack<IEnumerator<string>>();
        bool complete = true;
        int sliceFiles = 0;
        try
        {
            Open(root);
            while (cursors.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string path;
                try
                {
                    if (!cursors.Peek().MoveNext()) { cursors.Pop().Dispose(); continue; }
                    path = cursors.Peek().Current;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { cursors.Pop().Dispose(); complete = false; gap("DirectoryEnumerationFailed"); continue; }
                FileAttributes attributes;
                try { attributes = File.GetAttributes(path); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { complete = false; gap("EntryAttributesUnavailable"); continue; }
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                { complete = false; gap("ReparseTargetNotFollowed"); continue; }
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if (cursors.Count >= 128) { complete = false; gap("DirectoryDepthBudget"); continue; }
                    Open(path);
                }
                else
                {
                    await inspect(path, cancellationToken).ConfigureAwait(false);
                    // Yield between slices while retaining the actual traversal cursor.
                    if (++sliceFiles >= 128) { sliceFiles = 0; await Task.Delay(10, cancellationToken).ConfigureAwait(false); }
                }
            }
        }
        finally { while (cursors.Count > 0) cursors.Pop().Dispose(); }
        return complete;

        void Open(string directory)
        {
            try
            {
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                { complete = false; gap("ReparseRootNotFollowed"); return; }
                cursors.Push(Directory.EnumerateFileSystemEntries(directory).GetEnumerator());
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { complete = false; gap("DirectoryUnavailable"); }
        }
    }
}
