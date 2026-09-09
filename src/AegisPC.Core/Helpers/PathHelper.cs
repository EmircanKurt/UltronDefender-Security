using System;
using System.IO;
using AegisPC.Core.Constants;

namespace AegisPC.Core.Helpers;

public static class PathHelper
{
    public static string CanonicalizePath(string path) => Path.GetFullPath(path).TrimEnd('\\');

    /// <summary>Returns true only when path is root or a child of root at a directory boundary.</summary>
    public static bool IsPathUnder(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(root)) return false;
        try
        {
            var canonicalPath = Path.GetFullPath(path).TrimEnd('\\');
            var canonicalRoot = Path.GetFullPath(root).TrimEnd('\\');
            return canonicalPath.Equals(canonicalRoot, StringComparison.OrdinalIgnoreCase) ||
                   canonicalPath.StartsWith(canonicalRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static bool IsSystemPath(string path) => IsPathUnder(path, KnownPaths.WindowsDir);
    public static bool IsKnownSafePath(string path) => IsSystemPath(path) ||
                                                       IsPathUnder(path, KnownPaths.ProgramFiles) ||
                                                       IsPathUnder(path, KnownPaths.ProgramFilesX86);
    public static bool IsTempPath(string path) => IsPathUnder(path, KnownPaths.Temp);
    public static bool IsUserDownloadsPath(string path) => IsPathUnder(path, KnownPaths.Downloads);

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

    /// <summary>
    /// Verifies whether a file path is located within a recognized legitimate game library directory.
    /// In accordance with Rule 7.1 (No Magic Strings), arbitrary pirate repack keywords (e.g. 'fitgirl', 'dodi')
    /// are strictly excluded to prevent malware from obtaining security exemptions via directory naming.
    /// </summary>
    public static bool IsGameOrRepackDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        // A directory name is attacker-controlled input and cannot grant a security exemption.
        return false;
    }

    private static readonly string[] DevelopmentPackageMarkers = new[]
    {
        @"\site-packages\", @"\dist-packages\", @"\.venv\", @"\venv\", @"\env\",
        @"\.conda\", @"\conda-meta\", @"\node_modules\", @"\.nuget\packages\",
        @"\.cargo\registry\", @"\.rustup\", @"\lib\python", @"\programs\python\",
        @"\appdata\roaming\python\", @"\appdata\local\programs\python\",
        @"\pip-wheel-metadata\", @"\.gradle\caches\", @"\.m2\repository\"
    };

    /// <summary>
    /// Verilen dosya yolunun meşru bir geliştirme kütüphanesi veya paket yöneticisi dizininde
    /// (Python site-packages, venv, conda, node_modules, nuget, cargo vb.) bulunup bulunmadığını doğrular.
    /// </summary>
    public static bool IsDevelopmentOrPackageDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var lower = path.ToLowerInvariant();
        foreach (var marker in DevelopmentPackageMarkers)
        {
            if (lower.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static string ExtractExecutablePath(string rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand)) return string.Empty;
        var trimmed = rawCommand.Trim();
        if (trimmed.StartsWith("\""))
        {
            int nextQuote = trimmed.IndexOf('"', 1);
            if (nextQuote > 1)
            {
                return trimmed.Substring(1, nextQuote - 1);
            }
        }
        int firstSpace = trimmed.IndexOf(' ');
        return firstSpace > 0 ? trimmed.Substring(0, firstSpace) : trimmed;
    }

    public static bool ValidateFilePath(string path) => !string.IsNullOrWhiteSpace(path) && File.Exists(path);
}
