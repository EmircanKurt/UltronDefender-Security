using System.Text.Json;

namespace Ultron.PortableInspection;

/// <summary>Captures a completed report collection and its scope before asynchronous picker or output operations.</summary>
public sealed class InspectionExportSnapshot
{
    private readonly byte[] _serialized;

    private InspectionExportSnapshot(string selectedScope, string outcome, IEnumerable<InspectionReport> reports)
    {
        SelectedScope = selectedScope; Outcome = outcome;
        Reports = Array.AsReadOnly(reports.ToArray());
        _serialized = JsonSerializer.SerializeToUtf8Bytes(this, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Identifies the bounded manual preview independently of later GUI state.</summary>
    public string Product => "Ultron Linux manual preview";
    /// <summary>Returns the schema version of this exported snapshot.</summary>
    public int ReportVersion => 1;
    /// <summary>Records capture time before any asynchronous export dialog is shown.</summary>
    public DateTimeOffset GeneratedAtUtc { get; } = DateTimeOffset.UtcNow;
    /// <summary>Returns the scope that actually produced these reports, even after another scope is selected.</summary>
    public string SelectedScope { get; }
    /// <summary>Preserves cancellation, failure or completed-with-coverage state at capture time.</summary>
    public string Outcome { get; }
    /// <summary>Explicitly denies a malware-free assertion for every preview export.</summary>
    public bool MalwareFreeClaim => false;
    /// <summary>Lists missing platform capabilities and analyzers without changing inspection authority.</summary>
    public IReadOnlyList<string> Unsupported { get; } = Array.AsReadOnly(new[]
    { "Windows RT/ETW", "Defender", "Authenticode", "WFP", "Quarantine", "Process termination", "Full script semantics", "Deep PE/ELF" });
    /// <summary>Returns an owned read-only collection unaffected by clearing or appending the source GUI list.</summary>
    public IReadOnlyList<InspectionReport> Reports { get; }

    /// <summary>Captures the report payload synchronously; later source collection or nested array changes cannot alter exported bytes.</summary>
    public static InspectionExportSnapshot Capture(string selectedScope, string outcome, IEnumerable<InspectionReport> reports)
    {
        ArgumentNullException.ThrowIfNull(reports);
        return new(selectedScope, outcome, reports);
    }

    /// <summary>Serializes only the captured scope and reports; output errors and cancellation propagate to the GUI.</summary>
    public async Task WriteAsync(Stream output, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(output);
        for (int offset = 0; offset < _serialized.Length; offset += 64 * 1024)
            await output.WriteAsync(_serialized.AsMemory(offset, Math.Min(64 * 1024, _serialized.Length - offset)), cancellationToken);
    }
}
