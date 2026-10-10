using System.Diagnostics;
using System.Text.Json;

namespace AegisPC.BrowserSecurity.Browser;

internal sealed class BrowserMetadataReader
{
    internal const int MaximumProfiles = 64;
    internal const int MaximumExtensions = 512;
    internal const int MaximumVersions = 32;
    private const int MaximumIssues = 128;
    private long _remainingBytes = 16 * 1024 * 1024;
    internal List<BrowserInventoryIssue> Issues { get; } = new();
    internal long IssueCount { get; private set; }

    internal bool? ProbeDirectory(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.Directory) != 0) return true;
            AddIssue("MetadataRootIsNotDirectory", path);
            return null;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return false; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { AddIssue($"MetadataRootUnavailable:{ex.GetType().Name}", path); return null; }
    }

    internal void AddIssue(string code, string path)
    {
        IssueCount++;
        if (Issues.Count < MaximumIssues)
            Issues.Add(new BrowserInventoryIssue { Code = code, MetadataPath = path });
        Trace.WriteLine($"Browser Defender inventory gap: {code}.");
    }

    internal JsonDocument? ReadJson(string path, int maximumBytes = 4 * 1024 * 1024)
    {
        try
        {
            if (!File.Exists(path)) { AddIssue("MetadataMissing", path); return null; }
            if (!IsOrdinaryPath(path)) { AddIssue("ReparsePointUnsupported", path); return null; }
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
            if (stream.Length > maximumBytes || stream.Length > _remainingBytes)
            { AddIssue("MetadataBudgetExceeded", path); return null; }
            // Charge actual bytes, including concurrent growth, before parsing any JSON.
            using var memory = new MemoryStream();
            var buffer = new byte[4096];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                _remainingBytes -= read;
                if (_remainingBytes < 0 || memory.Length + read > maximumBytes)
                { AddIssue("MetadataBudgetExceeded", path); return null; }
                memory.Write(buffer, 0, read);
            }
            memory.Position = 0;
            return JsonDocument.Parse(memory, new JsonDocumentOptions { MaxDepth = 64 });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
            or ArgumentException or NotSupportedException)
        { AddIssue($"MetadataReadFailed:{ex.GetType().Name}", path); return null; }
    }

    internal IReadOnlyList<string> Directories(string path, int limit, string pattern = "*")
    {
        try
        {
            if (ProbeDirectory(path) != true) return Array.Empty<string>();
            if (!IsOrdinaryPath(path)) { AddIssue("ReparsePointUnsupported", path); return Array.Empty<string>(); }
            var results = Directory.EnumerateDirectories(path, pattern).Take(limit + 1).ToList();
            if (results.Count > limit) { AddIssue("DirectoryLimitExceeded", path); results.RemoveAt(limit); }
            return results.Where(item =>
            {
                if (IsOrdinaryPath(item)) return true;
                AddIssue("ReparsePointUnsupported", item);
                return false;
            }).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        { AddIssue($"DirectoryReadFailed:{ex.GetType().Name}", path); return Array.Empty<string>(); }
    }

    internal static bool IsOrdinaryPath(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            for (var current = full; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) return false;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        { Trace.WriteLine($"Browser Defender metadata path unavailable: {ex.GetType().Name}."); return false; }
    }

    internal static string Text(JsonElement element, string property, string fallback = "") =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : fallback;

    internal static bool TryObject(JsonElement element, string property, out JsonElement value)
    {
        value = default;
        return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out value)
            && value.ValueKind == JsonValueKind.Object;
    }

    internal List<string> Strings(JsonElement root, string property, string path)
    {
        if (root.ValueKind != JsonValueKind.Object)
        { AddIssue("ManifestStringArrayObjectUnsupported", path); return new(); }
        if (!root.TryGetProperty(property, out var items)) return new();
        if (items.ValueKind != JsonValueKind.Array)
        { AddIssue("ManifestStringArrayUnsupported", path); return new(); }
        if (items.GetArrayLength() > 512) AddIssue("ManifestStringArrayLimitExceeded", path);
        var values = new List<string>();
        foreach (var item in items.EnumerateArray().Take(512))
        {
            var value = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
            if (value is null || value.Length is 0 or > 2048)
                AddIssue("ManifestStringArrayItemUnsupported", path);
            else values.Add(value);
        }
        return values.Distinct(StringComparer.Ordinal).ToList();
    }
}
