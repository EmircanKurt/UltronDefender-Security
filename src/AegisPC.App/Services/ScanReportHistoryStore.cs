using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.App.Services;

/// <summary>Stores at most 50 actual scan result snapshots for the current Windows user; it does not certify protection or detection efficacy.</summary>
public sealed class ScanReportHistoryStore
{
    private const int MaximumRecords = 50;
    private const int MaximumBytes = 4 * 1024 * 1024;
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Creates a per-user history store, or an isolated store at the supplied absolute path for tests.</summary>
    public ScanReportHistoryStore(string? path = null)
    {
        _path = Path.GetFullPath(path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UltronDefender", "Reports", "scan-history.json"));
    }

    /// <summary>Reads bounded history; malformed or inaccessible data is reported to the caller, never represented as an empty successful history.</summary>
    public async Task<IReadOnlyList<ScanReportRecord>> LoadAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try { return await ReadCoreAsync().ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    /// <summary>Atomically saves a detached completed, cancelled, or failed result; running results and over-size data are rejected.</summary>
    public async Task AppendAsync(ScanReportRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(record.Result);
        ArgumentNullException.ThrowIfNull(record.Actions);
        if (record.Result.Status == ScanStatus.Running) throw new ArgumentException("A running scan is not a final report.", nameof(record));
        if (record.Result.Findings == null || !Enum.IsDefined(record.Result.Status)) throw new ArgumentException("The final scan result is invalid.", nameof(record));
        byte[] snapshotBytes = JsonSerializer.SerializeToUtf8Bytes(record, JsonOptions);
        var snapshot = JsonSerializer.Deserialize<ScanReportRecord>(snapshotBytes, JsonOptions) ?? throw new InvalidDataException("The report snapshot is empty.");
        await _gate.WaitAsync().ConfigureAwait(false);
        string staging = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var records = (await ReadCoreAsync().ConfigureAwait(false)).ToList();
            records.RemoveAll(r => r.Id == snapshot.Id);
            records.Insert(0, snapshot);
            records = records.Take(MaximumRecords).ToList();
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(records, JsonOptions);
            if (bytes.Length > MaximumBytes) throw new InvalidDataException("Report history exceeds the 4 MiB storage limit; no data was overwritten.");
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await File.WriteAllBytesAsync(staging, bytes).ConfigureAwait(false);
            File.Move(staging, _path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(staging)) File.Delete(staging); }
            catch (Exception ex) { Serilog.Log.Warning(ex, "Could not remove report history staging file {Path}", staging); }
            _gate.Release();
        }
    }

    private async Task<IReadOnlyList<ScanReportRecord>> ReadCoreAsync()
    {
        if (!File.Exists(_path)) return Array.Empty<ScanReportRecord>();
        await using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, useAsync: true);
        if (stream.Length > MaximumBytes) throw new InvalidDataException("Report history exceeds the 4 MiB read limit.");
        var records = await JsonSerializer.DeserializeAsync<List<ScanReportRecord>>(stream, JsonOptions).ConfigureAwait(false)
            ?? throw new InvalidDataException("Report history contains no valid document.");
        if (records.Count > MaximumRecords || records.Any(r => r == null || r.Result == null || r.Result.Findings == null || r.Actions == null || r.Result.Status == ScanStatus.Running || !Enum.IsDefined(r.Result.Status)))
            throw new InvalidDataException("Report history contains invalid or non-final results.");
        return records;
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, MaxDepth = 32 };
}

/// <summary>A detached final scan snapshot and confirmed UI action labels; mutable UI collections are not used as evidence.</summary>
public sealed class ScanReportRecord
{
    /// <summary>Identifies the stored report so subsequent confirmed actions update the same record instead of duplicating it.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();
    /// <summary>Contains the actual final engine result, including cancelled status, failures, and original findings.</summary>
    public ScanResult Result { get; set; } = new();
    /// <summary>Describes the resource profile observed by the UI; it is not a measured performance guarantee.</summary>
    public string ResourceProfile { get; set; } = string.Empty;
    /// <summary>Contains action labels backed by successful user operations, keyed by finding object path.</summary>
    public Dictionary<string, string> Actions { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Provides a readable timestamp for the report picker.</summary>
    [JsonIgnore] public string DateText => Result.StartedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");
    /// <summary>Distinguishes completed, cancelled, and failed scan reports.</summary>
    [JsonIgnore] public string StatusText => Result.Status switch { ScanStatus.Completed => "Tamamlandı", ScanStatus.Cancelled => "İptal edildi", ScanStatus.Failed => "Başarısız", _ => "Bilinmeyen" };
    /// <summary>Shows result counts without certifying files that were not inspected.</summary>
    [JsonIgnore] public string Summary => $"{Result.ScanType} • {StatusText} • {Result.ScannedFiles:N0} dosya • {Result.Findings.Count:N0} bulgu • {Result.FailedFiles:N0} hata";
}
