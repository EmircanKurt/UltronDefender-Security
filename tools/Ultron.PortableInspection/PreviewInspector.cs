using System.IO.Compression;
using System.Security.Cryptography;
using AegisPC.Core.Models;
using AegisPC.Security.Detection.YaraEngine;
using AegisPC.Security.Scanning;

namespace Ultron.PortableInspection;

/// <summary>Inspects caller-owned immutable bytes with the shared managed classifier and rule subset.</summary>
public sealed class PreviewInspector
{
    private readonly IYaraEngine? _rules;

    /// <summary>Accepts the shared managed rule engine; absent rules are recorded as missing inspection coverage.</summary>
    public PreviewInspector(IYaraEngine? rules = null) => _rules = rules;

    /// <summary>Inspects a complete bounded snapshot; omissions remain explicit and input is never executed.</summary>
    public Task<InspectionReport> InspectAsync(string path, byte[] bytes, InspectionLimits? limits = null, CancellationToken cancellationToken = default)
        => InspectSnapshotAsync(path, bytes, limits ?? new(), true, cancellationToken);

    private async Task<InspectionReport> InspectSnapshotAsync(string path, byte[] bytes, InspectionLimits limits, bool inspectArchive, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        limits.Validate();
        ct.ThrowIfCancellationRequested();
        if (limits.MaximumFileBytes <= 0 || bytes.Length > limits.MaximumFileBytes)
            return new() { Path = path, Limitations = ["File snapshot exceeds the configured byte budget."] };
        using var source = new MemoryStream(bytes, writable: false);
        var classification = await new FileContentClassifier().ClassifyAsync(source, System.IO.Path.GetExtension(path), ct);
        var gaps = new List<string>(classification.CoverageLimitations);
        var indicators = new List<string>();
        if (_rules == null || _rules.LoadedRuleCount == 0) gaps.Add("No managed preview rule snapshot is loaded.");
        else indicators.AddRange((await _rules.ScanBufferAsync(bytes, path, ct)).Select(match => $"MiniYARA review: {match.RuleName}"));
        AddUnsupportedCoverage(classification, gaps);
        InspectionReport[] members = [];
        if (classification.RequiresZipInspection)
        {
            if (!inspectArchive) gaps.Add("Nested archive member content is unsupported by this preview.");
            else if (classification.ValidatedFormats.Contains(FileContentFormat.Zip))
                members = await InspectZipAsync(path, bytes, limits, gaps, ct);
            else gaps.Add("ZIP member inspection requires a validated supported ZIP directory.");
            foreach (var member in members)
                indicators.AddRange(member.ReviewIndicators.Select(indicator => $"Member {member.Path}: {indicator}"));
        }
        ct.ThrowIfCancellationRequested();
        return new()
        {
            Path = path, Sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
            Formats = classification.Formats.Select(format => format.ToString()).ToArray(),
            ReviewIndicators = indicators.ToArray(), Limitations = gaps.Distinct(StringComparer.Ordinal).ToArray(),
            ChecksComplete = classification.IsComplete && gaps.Count == 0, Members = members
        };
    }

    private static void AddUnsupportedCoverage(FileContentClassification classification, List<string> gaps)
    {
        if (classification.Formats.Contains(FileContentFormat.PortableExecutable))
            gaps.Add("PE structural classification only: imports, Authenticode, deep PE analysis and Windows providers are unsupported.");
        if (classification.Formats.Any(format => format is FileContentFormat.Text or FileContentFormat.ScriptCandidate))
            gaps.Add("Windows script behavior providers and full script semantic analysis are unsupported; local rule matches are review indicators.");
        if (classification.Formats.Any(format => format is FileContentFormat.Pdf or FileContentFormat.Png or FileContentFormat.Jpeg or FileContentFormat.WindowsShortcut))
            gaps.Add("Embedded payload decoding and platform-specific analyzers are unsupported for this format.");
    }

    private async Task<InspectionReport[]> InspectZipAsync(string path, byte[] bytes, InspectionLimits limits, List<string> gaps, CancellationToken ct)
    {
        var reports = new List<InspectionReport>();
        long expanded = 0;
        try
        {
            using var source = new MemoryStream(bytes, writable: false);
            using var zip = new ZipArchive(source, ZipArchiveMode.Read);
            foreach (var entry in zip.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (reports.Count >= limits.MaximumArchiveEntries) { gaps.Add("Archive entry count budget was reached."); break; }
                if (entry.FullName.EndsWith("/", StringComparison.Ordinal)) continue;
                if (entry.Length < 0 || entry.Length > limits.MaximumFileBytes || entry.Length > limits.MaximumExpandedBytes - expanded)
                { gaps.Add("Archive expanded byte budget was reached."); break; }
                expanded += entry.Length;
                byte[] content = new byte[checked((int)entry.Length)];
                using var member = entry.Open();
                await member.ReadExactlyAsync(content, ct);
                byte[] extra = new byte[1];
                if (await member.ReadAsync(extra, ct) != 0) throw new InvalidDataException("Archive member exceeds its declared length.");
                var report = await InspectSnapshotAsync($"{path} :: {entry.FullName}", content, limits, false, ct);
                reports.Add(report);
                if (!report.ChecksComplete) gaps.Add("At least one archive member has incomplete or unsupported inspection coverage.");
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException)
        { gaps.Add("Archive member inspection failed: " + ex.Message); }
        return reports.ToArray();
    }
}
