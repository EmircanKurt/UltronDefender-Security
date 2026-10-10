using System.Text.Json;
using Ultron.ThreatIntel.Collector;

// Deliberately not installed/referenced by the endpoint. Never pass a key on the command line.
if (args.Length != 1 || !args[0].EndsWith(".intel-collection.json", StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("Usage: Ultron.ThreatIntel.Collector <new-private-report.intel-collection.json>. Set ULTRON_MB_AUTH_KEY locally; never commit it.");
    return 2;
}
string? apiKey = Environment.GetEnvironmentVariable("ULTRON_MB_AUTH_KEY");
if (string.IsNullOrWhiteSpace(apiKey)) { Console.Error.WriteLine("Developer API credential is not configured."); return 2; }
using var handler = new HttpClientHandler { AllowAutoRedirect = false };
using var client = new HttpClient(handler);
using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
var result = await new MetadataCollector(client).CollectAsync(apiKey, cancellationToken: cancel.Token);
await using var output = new FileStream(Path.GetFullPath(args[0]), FileMode.CreateNew, FileAccess.Write, FileShare.None);
await JsonSerializer.SerializeAsync(output, result, new JsonSerializerOptions { WriteIndented = true });
Console.WriteLine($"{result.Status}: {result.Records.Count} metadata records; {result.Code}. Unsigned review data, not an active signature package.");
return result.Status is CollectionStatus.Failed or CollectionStatus.Cancelled or CollectionStatus.Timeout or CollectionStatus.Partial or CollectionStatus.CoverageGap ? 1 : 0;
