using System.Net.Http;
using System.IO;
using System.Text.Json;
using AegisPC.Contracts.ThreatIntelligence;

namespace Ultron.ThreatIntel.Collector;

/// <summary>Collection status is not an endpoint verdict or a malware detection rate.</summary>
public enum CollectionStatus { CompleteWindow, NoResults, Partial, CoverageGap, Failed, Cancelled, Timeout }
/// <summary>Unsigned metadata for developer review; the family label cannot authorize a verdict.</summary>
public sealed record CollectedMetadata(string Sha256, string Family, string SourceReference, DateTimeOffset AcquiredAtUtc);
/// <summary>Reports this response's time window separately from missing history and partial records.</summary>
public sealed record CollectionReport(CollectionStatus Status, DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc, bool HasCoverageGap, string Code, IReadOnlyList<CollectedMetadata> Records);

/// <summary>
/// Developer-only metadata collector. The only query is get_recent/time; it cannot fetch samples,
/// upload files, or submit endpoint hashes. No redirect, arbitrary URL or analysis-link fetching.
/// </summary>
public sealed class MetadataCollector(HttpClient client)
{
    /// <summary>Response byte ceiling, enforced on declared and streamed lengths.</summary>
    public const int MaxResponseBytes = 8 * 1024 * 1024;
    /// <summary>Maximum visited rows before a response is reported partial.</summary>
    public const int MaxRecords = 5000;
    /// <summary>Fixed official metadata endpoint; caller-provided URLs are not accepted.</summary>
    public static readonly Uri Endpoint = new("https://mb-api.abuse.ch/api/v1/");

    /// <summary>
    /// Queries only the last 60 minutes. Older gaps remain gaps, including on empty results.
    /// Credentials are never returned or logged. Caller cancellation and timeout are distinct.
    /// The injected client must have redirects disabled in the developer composition root.
    /// </summary>
    public async Task<CollectionReport> CollectAsync(string apiKey, DateTimeOffset? lastCompletedWindowEndUtc = null,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset end = DateTimeOffset.UtcNow;
        DateTimeOffset start = end.AddHours(-1);
        bool gap = !lastCompletedWindowEndUtc.HasValue || lastCompletedWindowEndUtc.Value < start;
        CollectionReport Result(CollectionStatus status, string code, IReadOnlyList<CollectedMetadata>? records = null) =>
            new(status, start, end, gap, code, records ?? Array.Empty<CollectedMetadata>());
        if (cancellationToken.IsCancellationRequested) return Result(CollectionStatus.Cancelled, "CallerCancelled");
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length > 512 || apiKey.Any(c => c <= ' ' || c >= 127))
            return Result(CollectionStatus.Failed, "CredentialMissingOrInvalid");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint);
            request.Headers.Add("Auth-Key", apiKey);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                { ["query"] = "get_recent", ["selector"] = "time" });
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode) return Result(CollectionStatus.Failed, "HttpRejected");
            if (response.Content.Headers.ContentLength > MaxResponseBytes) return Result(CollectionStatus.Failed, "ResponseTooLarge");
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var bytes = new MemoryStream();
            var buffer = new byte[8192];
            while (true)
            {
                int count = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length,
                    MaxResponseBytes + 1 - (int)bytes.Length)), timeout.Token);
                if (count == 0) break;
                if (bytes.Length + count > MaxResponseBytes) return Result(CollectionStatus.Failed, "ResponseTooLarge");
                bytes.Write(buffer, 0, count);
            }
            return Parse(bytes.ToArray(), start, end, gap);
        }
        catch (OperationCanceledException)
        { return Result(cancellationToken.IsCancellationRequested ? CollectionStatus.Cancelled : CollectionStatus.Timeout,
            cancellationToken.IsCancellationRequested ? "CallerCancelled" : "RequestTimedOut"); }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException)
        { return Result(CollectionStatus.Failed, "TransportOrResponseInvalid"); }
    }

    private static CollectionReport Parse(byte[] bytes, DateTimeOffset start, DateTimeOffset end, bool gap)
    {
        var records = new List<CollectedMetadata>();
        CollectionReport Result(CollectionStatus status, string code) => new(status, start, end, gap, code, records);
        using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        if (doc.RootElement.ValueKind != JsonValueKind.Object ||
            !doc.RootElement.TryGetProperty("query_status", out var status) || status.ValueKind != JsonValueKind.String)
            return Result(CollectionStatus.Failed, "QueryStatusMissing");
        if (status.GetString() == "no_results") return Result(gap ? CollectionStatus.CoverageGap : CollectionStatus.NoResults, "NoResults");
        if (status.GetString() != "ok" || !doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            return Result(CollectionStatus.Failed, "QueryRejected");
        bool partial = data.GetArrayLength() > MaxRecords;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int visited = 0;
        foreach (var item in data.EnumerateArray())
        {
            if (++visited > MaxRecords) break;
            if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("sha256_hash", out var hash) ||
                hash.ValueKind != JsonValueKind.String || !Sha256Identity.IsValid(hash.GetString()))
            { partial = true; continue; }
            string sha = hash.GetString()!.ToUpperInvariant();
            if (!seen.Add(sha)) continue;
            string family = "Unlabeled";
            if (item.TryGetProperty("signature", out var sig) && sig.ValueKind == JsonValueKind.String)
            {
                string? label = sig.GetString();
                if (label is { Length: > 0 and <= 256 } && !label.Any(char.IsControl)) family = label;
                else if (label is { Length: > 256 }) partial = true;
            }
            records.Add(new(sha, family, $"https://bazaar.abuse.ch/sample/{sha.ToLowerInvariant()}/", end));
        }
        return Result(partial ? CollectionStatus.Partial : gap ? CollectionStatus.CoverageGap :
            records.Count == 0 ? CollectionStatus.NoResults : CollectionStatus.CompleteWindow,
            partial ? "IncompleteResponse" : gap ? "PriorIntervalNotCovered" : "WindowCollected");
    }
}
