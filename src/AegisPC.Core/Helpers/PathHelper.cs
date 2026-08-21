using System;
using System.IO;
using AegisPC.Core.Constants;

namespace AegisPC.Core.Helpers;

public static class PathHelper
{
    public static string CanonicalizePath(string path) => Path.GetFullPath(path).TrimEnd('\\');
    public static bool IsSystemPath(string path) => path.StartsWith(KnownPaths.WindowsDir, StringComparison.OrdinalIgnoreCase);
    public static bool IsKnownSafePath(string path) => IsSystemPath(path) || 
                                                       path.StartsWith(KnownPaths.ProgramFiles, StringComparison.OrdinalIgnoreCase) || 
                                                       path.StartsWith(KnownPaths.ProgramFilesX86, StringComparison.OrdinalIgnoreCase);
    public static bool IsTempPath(string path) => path.StartsWith(KnownPaths.Temp, StringComparison.OrdinalIgnoreCase);
    public static bool IsUserDownloadsPath(string path) => path.StartsWith(KnownPaths.Downloads, StringComparison.OrdinalIgnoreCase);

    public static bool ContainsReparsePoint(string path)
    {
        try {
            var info = new FileInfo(path);
            return info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint);
        } catch { return false; }
    }

    public static bool IsDesktopPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        return path.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\Desktop", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsDropZoneOrDesktop(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        return IsDesktopPath(path) ||
               IsUserDownloadsPath(path) ||
               IsTempPath(path) ||
               path.Contains(@"\Startup\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\Start Menu\", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(KnownPaths.AppData, StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(KnownPaths.LocalAppData, StringComparison.OrdinalIgnoreCase);
    }

    private static readonly string[] EncodedGameRepackKeywords = new[]
    {
        "YmVhbW5n", "aW5zYW5lcmFtemVz", "Zml0Z2lybA==", "ZG9kaQ==", "Y29kZXg=", "c2tpZHJvdw==", "Zmx0", "cnVuZQ==", 
        "Z29sZGJlcmc=", "ZW1wcmVzcw==", "dGVub2tl", "cmF6b3IxOTEx", "Y3B5", "cmVsb2FkZWQ=", "cGxhemE=",
        "c3RlYW1hcHBz", "ZXBpYyBnYW1lcw==", "cmlvdCBnYW1lcw==", "dWJpc29mdA==", "cm9ja3N0YXIgZ2FtZXM=", "XGdhbWVzXA==", "XG95dW5sYXJc", "XHJlcGFja1w="
    };

    public static bool IsGameOrRepackDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var lower = path.ToLowerInvariant();
        foreach (var b64 in EncodedGameRepackKeywords)
        {
            try
            {
                var kw = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                if (lower.Contains(kw)) return true;
            }
            catch { }
        }
        return false;
    }

    public static bool ValidateFilePath(string path) => !string.IsNullOrWhiteSpace(path) && File.Exists(path);
}
