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

    private static readonly string[] GameRepackKeywords = new[]
    {
        "beamng", "insaneramzes", "fitgirl", "dodi", "codex", "skidrow", "flt", "rune", 
        "goldberg", "empress", "tenoke", "razor1911", "cpy", "reloaded", "plaza",
        "steamapps", "epic games", "riot games", "ubisoft", "rockstar games", "gog games", "gog galaxy",
        "ea games", "origin games", "battle.net", "xboxgames", @"\games\", @"\oyunlar\", @"\repack\",
        "modorganizer", "vortex", "curseforge", "minecraft", ".minecraft", "roblox", "unity", "unreal"
    };

    public static bool IsGameOrRepackDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var lower = path.ToLowerInvariant();
        foreach (var kw in GameRepackKeywords)
        {
            if (lower.Contains(kw, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    public static bool ValidateFilePath(string path) => !string.IsNullOrWhiteSpace(path) && File.Exists(path);
}
