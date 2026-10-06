using System.Net;
using System.Net.Http;
using System.Text;
using Ultron.ThreatIntel.Collector;
using Xunit;

namespace AegisPC.Tests;

/// <summary>HTTP handler fixtures only; no network, API secret, sample download or endpoint hash upload.</summary>
public sealed class MetadataCollectorReviewTests
{
    private const string Hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> reply) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) { Calls++; return reply(request, ct); }
    }
    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    [Fact]
    public async Task OnlyDocumentedRecentMetadataQueryIsSent()
    {
        using var handler = new Handler(async (request, ct) =>
        {
            Assert.Equal(MetadataCollector.Endpoint, request.RequestUri);
            Assert.Equal("inert-development-key", Assert.Single(request.Headers.GetValues("Auth-Key")));
            Assert.Equal("query=get_recent&selector=time", await request.Content!.ReadAsStringAsync(ct));
            return Json($"{{\"query_status\":\"ok\",\"data\":[{{\"sha256_hash\":\"{Hash}\",\"signature\":\"FamilyLabelOnly\"}}]}}");
        });
        using var client = new HttpClient(handler);
        var report = await new MetadataCollector(client).CollectAsync("inert-development-key", DateTimeOffset.UtcNow.AddMinutes(-30));
        Assert.Equal(CollectionStatus.CompleteWindow, report.Status);
        Assert.Equal("FamilyLabelOnly", Assert.Single(report.Records).Family);
        Assert.False(client.DefaultRequestHeaders.Contains("Auth-Key"));
    }

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("bad\r\nheader")] [InlineData("key value")]
    public async Task InvalidCredentialCannotCreateRequest(string? key)
    {
        using var handler = new Handler((_, _) => throw new InvalidOperationException("must not send"));
        using var client = new HttpClient(handler);
        Assert.Equal(CollectionStatus.Failed, (await new MetadataCollector(client).CollectAsync(key!)).Status);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task EmptyAndOldIntervalDoesNotPretendToCoverPastDay()
    {
        using var handler = new Handler((_, _) => Task.FromResult(Json("{\"query_status\":\"no_results\"}")));
        using var client = new HttpClient(handler);
        var result = await new MetadataCollector(client).CollectAsync("inert", DateTimeOffset.UtcNow.AddDays(-1));
        Assert.Equal(CollectionStatus.CoverageGap, result.Status); Assert.True(result.HasCoverageGap);
        Assert.Equal(TimeSpan.FromHours(1), result.WindowEndUtc - result.WindowStartUtc);
    }

    [Fact]
    public async Task InvalidRowMakesUpdatePartialAndRetainsUsableMetadata()
    {
        using var handler = new Handler((_, _) => Task.FromResult(Json($"{{\"query_status\":\"ok\",\"data\":[{{\"sha256_hash\":\"{Hash}\"}},{{\"sha256_hash\":\"NOT-SHA256\"}}]}}")));
        using var client = new HttpClient(handler);
        var result = await new MetadataCollector(client).CollectAsync("inert", DateTimeOffset.UtcNow);
        Assert.Equal(CollectionStatus.Partial, result.Status); Assert.Single(result.Records);
    }

    [Fact]
    public async Task OversizeAndMalformedResponsesAreRejected()
    {
        using var handler = new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new ByteArrayContent(new byte[MetadataCollector.MaxResponseBytes + 1]) }));
        using var client = new HttpClient(handler);
        Assert.Equal("ResponseTooLarge", (await new MetadataCollector(client).CollectAsync("inert")).Code);
        using var bad = new Handler((_, _) => Task.FromResult(Json("[not-json")));
        using var badClient = new HttpClient(bad);
        Assert.Equal(CollectionStatus.Failed, (await new MetadataCollector(badClient).CollectAsync("inert")).Status);
    }

    [Fact]
    public async Task TimeoutAndCallerCancellationHaveDifferentResults()
    {
        using var handler = new Handler((_, _) => throw new OperationCanceledException());
        using var client = new HttpClient(handler);
        var collector = new MetadataCollector(client);
        Assert.Equal(CollectionStatus.Timeout, (await collector.CollectAsync("inert")).Status);
        using var cts = new CancellationTokenSource(); cts.Cancel();
        Assert.Equal(CollectionStatus.Cancelled, (await collector.CollectAsync("inert", cancellationToken: cts.Token)).Status);
        Assert.Equal(1, handler.Calls);
    }
}
