using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace AegisPC.Core.Helpers;

/// <summary>
/// Limits automatically discovered paths to local storage before existence checks or watcher/canary I/O.
/// This is a conservative routing check, not handle-pinned access authorization or race-free containment.
/// Explicitly selected manual network scans have a separate policy and must not use this filter.
/// </summary>
public static class ImplicitLocalPathPolicy
{
    /// <summary>
    /// Accepts fully qualified drive or volume-GUID syntax without accessing a token, disk or network.
    /// UNC, device namespaces, relative paths and alternate data stream syntax are rejected.
    /// </summary>
    public static bool HasLocalSyntax(string? path) => TryNormalize(path, out _, out _);

    /// <summary>
    /// Checks a local drive type and existing ancestors before consumers perform implicit path I/O.
    /// Unavailable storage, remote drives and reparse ancestors fail closed. A missing suffix is allowed
    /// so callers can separately report missing targets. Injectable readers keep decision tests inert.
    /// No key, file content or credential is read; directory attributes are not a TOCTOU guarantee.
    /// </summary>
    public static bool IsEligible(string? path, Func<string, DriveType>? driveTypeReader = null,
        Func<string, FileAttributes?>? attributeReader = null)
    {
        if (!TryNormalize(path, out string fullPath, out string root)) return false;
        try
        {
            DriveType type = (driveTypeReader ?? ReadDriveType)(root);
            if (type is not (DriveType.Fixed or DriveType.Removable or DriveType.Ram)) return false;
            var readAttributes = attributeReader ?? ReadAttributes;
            string current = root;
            if (!AcceptAncestor(current, readAttributes, out bool missing)) return false;
            if (missing) return true;
            foreach (string segment in fullPath[root.Length..].Split('\\', StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, segment);
                if (!AcceptAncestor(current, readAttributes, out missing)) return false;
                if (missing) return true;
            }
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            System.Security.SecurityException or ArgumentException or NotSupportedException)
        {
            Trace.TraceWarning("Implicit local path metadata is unavailable: {0}", exception.GetType().Name);
            return false;
        }
    }

    private static bool AcceptAncestor(string path, Func<string, FileAttributes?> reader, out bool missing)
    {
        FileAttributes? attributes = reader(path);
        missing = !attributes.HasValue;
        return missing || (attributes!.Value & FileAttributes.ReparsePoint) == 0;
    }

    private static bool TryNormalize(string? path, out string fullPath, out string root)
    {
        fullPath = root = string.Empty;
        if (string.IsNullOrWhiteSpace(path)) return false;
        string value = path.Replace('/', '\\');
        int prefixLength;
        if (value.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase))
        {
            const int guidStart = 11;
            int close = value.IndexOf('}', guidStart);
            if (close != guidStart + 36 || close + 1 >= value.Length || value[close + 1] != '\\' ||
                !Guid.TryParseExact(value.AsSpan(guidStart, 36), "D", out _)) return false;
            root = value[..(close + 2)];
            prefixLength = root.Length;
        }
        else
        {
            int driveStart = value.StartsWith(@"\\?\", StringComparison.Ordinal) ? 4 : 0;
            if (value.Length < driveStart + 3 || !char.IsAsciiLetter(value[driveStart]) ||
                value[driveStart + 1] != ':' || value[driveStart + 2] != '\\') return false;
            root = value[..(driveStart + 3)];
            prefixLength = root.Length;
        }
        if (value.AsSpan(prefixLength).IndexOfAny("\0:*?<>|\"".AsSpan()) >= 0) return false;
        // Extended paths do not necessarily normalize dot segments; reject them uniformly.
        if (value[prefixLength..].Split('\\').Any(segment => segment is "." or "..")) return false;
        try { fullPath = Path.GetFullPath(value); return fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        { return false; }
    }

    private static DriveType ReadDriveType(string root) => OperatingSystem.IsWindows()
        ? (DriveType)GetDriveTypeW(root) : DriveType.Unknown;

    private static FileAttributes? ReadAttributes(string path)
    {
        try { return File.GetAttributes(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetDriveTypeW(string rootPathName);
}
