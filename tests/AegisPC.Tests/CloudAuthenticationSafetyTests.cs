using System.IO;
using System.Net;
using System.Net.Http;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Reputation;
using AegisPC.Security.Scanning;
using Xunit;

namespace AegisPC.Tests;

/// <summary>
/// Verifies cloud authentication and unknown-result boundaries using an isolated
/// temporary signature database, in-memory settings, and inert HTTP responses.
/// No live request, confirmed malicious response, or user settings are used.
/// </summary>
[Collection("SequentialDiskTests")]
public sealed class CloudAuthenticationSafetyTests : IDisposable
{
    private const string TestHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string OtherHash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string MissingHashResponse = "{\"query_status\":\"hash_not_found\"}";
    private readonly string _sandboxDirectory;

    /// <summary>
    /// Isolates the static local signature store before any lookup can initialize
    /// its default user-profile database.
    /// </summary>
    public CloudAuthenticationSafetyTests()
    {
        _sandboxDirectory = Path.Combine(Path.GetTempPath(), "Aegis_CloudAuth_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_sandboxDirectory);
        ThreatSignatureDatabase.ResetForTesting(Path.Combine(_sandboxDirectory, "signatures.db"));
    }

    /// <summary>
    /// Releases SQLite pools and removes only this fixture's temporary store.
    /// </summary>
    public void Dispose()
    {
        ThreatSignatureDatabase.ResetForTesting();
        Directory.Delete(_sandboxDirectory, recursive: true);
    }

    /// <summary>
    /// A valid opt-in request carries the current key on that request alone and
    /// sends a normalized SHA-256 without writing settings.
    /// </summary>
    [Fact]
    public async Task AuthKey_IsAddedPerRequest_AndReflectsSettingsChanges()
    {
        var settings = new MemorySettings { ApiKey = "inert-key-one" };
        var observedKeys = new List<string>();
        var observedBodies = new List<string>();
        using var handler = new RecordingHandler(async (request, cancellationToken) =>
        {
            Assert.True(request.Headers.TryGetValues("Auth-Key", out var values));
            observedKeys.Add(Assert.Single(values));
            Assert.NotNull(request.Content);
            observedBodies.Add(await request.Content.ReadAsStringAsync(cancellationToken));
            return JsonResponse(MissingHashResponse);
        });
        using var client = new HttpClient(handler);
        using var service = new ReputationService(settings, httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash.ToUpperInvariant()));
        settings.ApiKey = "inert-key-two";
        AssertUnknown(await service.CheckReputationAsync(OtherHash));

        Assert.Equal(new[] { "inert-key-one", "inert-key-two" }, observedKeys);
        Assert.Equal(new[] { "query=get_info&hash=" + TestHash, "query=get_info&hash=" + OtherHash }, observedBodies);
        Assert.False(client.DefaultRequestHeaders.Contains("Auth-Key"));
        Assert.Equal(0, settings.WriteCount);
    }

    /// <summary>
    /// Missing keys and values unsuitable for an authentication header disable
    /// HTTP lookup without converting absence of cloud evidence into trust.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("key\r\ninjected-header")]
    [InlineData("key\tvalue")]
    [InlineData("key value")]
    [InlineData("key\u007fvalue")]
    public async Task MissingOrInvalidKey_ReturnsUnknownWithoutHttp(string? apiKey)
    {
        var settings = new MemorySettings { ApiKey = apiKey };
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(settings, httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(0, handler.CallCount);
        Assert.Equal(0, service.CacheCount);
        Assert.Equal(0, settings.WriteCount);
    }

    /// <summary>
    /// An absent settings provider cannot supply authentication and must not
    /// trigger anonymous requests even when lookup was explicitly enabled.
    /// </summary>
    [Fact]
    public async Task MissingSettingsProvider_ReturnsUnknownWithoutHttp()
    {
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(httpClient: client) { IsCloudLookupEnabled = true };

        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(0, handler.CallCount);
    }

    /// <summary>
    /// Configured authentication does not override the user's disabled cloud
    /// preference or produce a trusted fallback.
    /// </summary>
    [Fact]
    public async Task CloudOptOut_IsPreservedWhenKeyExists()
    {
        var settings = new MemorySettings { Enabled = false };
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(settings, httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(0, handler.CallCount);
    }

    /// <summary>
    /// Only complete hexadecimal SHA-256 digests may reach the network; invalid
    /// strings are not trimmed or accepted as other hash algorithms.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("0123456789abcdef0123456789abcdef")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0")]
    [InlineData("g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    [InlineData(" 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ")]
    public async Task InvalidSha256_ReturnsUnknownWithoutHttp(string hash)
    {
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(hash));

        Assert.Equal(0, handler.CallCount);
        Assert.Equal(0, service.CacheCount);
    }

    /// <summary>
    /// A genuine embedded local hash match remains available without cloud
    /// credentials; no bytes for the antivirus test file are created.
    /// </summary>
    [Fact]
    public async Task LocalHashEvidence_IsPreservedWithoutCloudKey()
    {
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings { ApiKey = null }, httpClient: client);

        var result = await service.CheckReputationAsync("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

        Assert.True(result.IsKnown);
        Assert.True(result.IsMalicious);
        Assert.Equal(100, result.Severity);
        Assert.Equal(0, handler.CallCount);
    }

    /// <summary>
    /// A hash absent from a malware catalogue remains unknown on both its first
    /// lookup and a cached lookup; catalogue absence never proves cleanliness.
    /// </summary>
    [Fact]
    public async Task HashNotFound_RemainsUnknownWhenCached()
    {
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));
        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(1, handler.CallCount);
    }

    /// <summary>
    /// A newly imported local signature overrides a cached cloud miss. The
    /// simulated record is written only to this fixture's temporary database.
    /// </summary>
    [Fact]
    public async Task NewlyLearnedLocalSignature_OverridesCachedCloudMiss()
    {
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));
        Assert.Equal(1, service.CacheCount);
        Assert.Equal(Path.Combine(_sandboxDirectory, "signatures.db"), ThreatSignatureDatabase.CurrentDbPath);
        Assert.Equal(1, ThreatSignatureDatabase.ImportThreatHashes(new[]
        {
            (TestHash, "Inert.Local.Test", "TestFixture", 85, "MalwareBazaar")
        }));

        var result = await service.CheckReputationAsync(TestHash);

        Assert.True(result.IsKnown);
        Assert.True(result.IsMalicious);
        Assert.Equal("Inert.Local.Test", result.ThreatName);
        Assert.Equal(85, result.Severity);
        Assert.Contains("Yerel", result.Source);
        Assert.Equal(1, handler.CallCount);
    }

    /// <summary>
    /// API failures and malformed success envelopes remain unknown and are not
    /// cached, allowing later requests to recover with corrected credentials.
    /// </summary>
    [Theory]
    [InlineData("{\"query_status\":\"no_api_key\"}")]
    [InlineData("{\"query_status\":\"illegal_api_key\"}")]
    [InlineData("{\"query_status\":\"rate_limit_exceeded\"}")]
    [InlineData("not-json")]
    [InlineData("[]")]
    [InlineData("{\"query_status\":7}")]
    [InlineData("{\"query_status\":\"ok\"}")]
    [InlineData("{\"query_status\":\"ok\",\"data\":[]}")]
    [InlineData("{\"query_status\":\"ok\",\"data\":[{}]}")]
    [InlineData("{\"query_status\":\"ok\",\"data\":[{\"sha256_hash\":\"invalid\"}]}")]
    [InlineData("{\"query_status\":\"ok\",\"data\":[{\"sha256_hash\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"}]}")]
    public async Task ApiFailureOrInvalidResponse_RemainsUnknownAndIsNotCached(string responseJson)
    {
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(responseJson)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));
        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(2, handler.CallCount);
        Assert.Equal(0, service.CacheCount);
    }

    /// <summary>
    /// Authentication, rate-limit, and service HTTP errors do not establish
    /// clean reputation and are retried on a later lookup.
    /// </summary>
    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task HttpFailure_RemainsUnknownAndIsNotCached(HttpStatusCode status)
    {
        using var handler = new RecordingHandler((_, _) => Task.FromResult(new HttpResponseMessage(status)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));
        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(2, handler.CallCount);
        Assert.Equal(0, service.CacheCount);
    }

    /// <summary>
    /// Network failures remain unknown and cannot hide future recovery behind
    /// an hour-long cached fallback.
    /// </summary>
    [Fact]
    public async Task NetworkFailure_RemainsUnknownAndIsNotCached()
    {
        using var handler = new RecordingHandler((_, _) => throw new HttpRequestException("Inert network failure."));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));
        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(2, handler.CallCount);
        Assert.Equal(0, service.CacheCount);
    }

    /// <summary>
    /// A streamed response with no declared length must stop reading after the
    /// size boundary and remain unknown without caching its partial JSON.
    /// </summary>
    [Fact]
    public async Task OversizedChunkedResponse_IsBoundedAndNotCached()
    {
        using var payload = new CountingPaddingStream(2 * 1024 * 1024);
        using var handler = new RecordingHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(payload)
        }));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(0, service.CacheCount);
        Assert.InRange(payload.BytesRead, 1024 * 1024 + 1, 1024 * 1024 + 8192);
    }

    /// <summary>
    /// A complete response exactly at the byte limit remains parseable; the
    /// limit is inclusive for an otherwise valid catalogue miss.
    /// </summary>
    [Fact]
    public async Task ResponseAtByteLimit_IsAccepted()
    {
        var json = MissingHashResponse + new string(' ', 1024 * 1024 - MissingHashResponse.Length);
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(json)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(1, service.CacheCount);
    }

    /// <summary>
    /// The service's bounded timeout produces unknown evidence without caching
    /// the outage or treating an unavailable cloud service as trust.
    /// </summary>
    [Fact]
    public async Task LookupTimeout_RemainsUnknownAndIsNotCached()
    {
        using var handler = new RecordingHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return JsonResponse(MissingHashResponse);
        });
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        AssertUnknown(await service.CheckReputationAsync(TestHash));

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(0, service.CacheCount);
    }

    /// <summary>
    /// Caller cancellation during HTTP is propagated and cannot be downgraded
    /// to a normal offline result by broad exception handling.
    /// </summary>
    [Fact]
    public async Task CallerCancellation_PropagatesAndDoesNotCacheFallback()
    {
        using var callerCancellation = new CancellationTokenSource();
        using var handler = new RecordingHandler(async (_, cancellationToken) =>
        {
            callerCancellation.Cancel();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return JsonResponse(MissingHashResponse);
        });
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings(), httpClient: client);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.CheckReputationAsync(TestHash, callerCancellation.Token));

        Assert.Equal(0, service.CacheCount);
    }

    /// <summary>
    /// Already-cancelled callers receive cancellation before validation or an
    /// offline fast path and no HTTP request is attempted.
    /// </summary>
    [Fact]
    public async Task PreCancelledCaller_PropagatesBeforeOfflineResult()
    {
        using var callerCancellation = new CancellationTokenSource();
        callerCancellation.Cancel();
        using var handler = new RecordingHandler((_, _) => Task.FromResult(JsonResponse(MissingHashResponse)));
        using var client = new HttpClient(handler);
        using var service = new ReputationService(new MemorySettings { ApiKey = null }, httpClient: client);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.CheckReputationAsync(string.Empty, callerCancellation.Token));

        Assert.Equal(0, handler.CallCount);
    }

    private static void AssertUnknown(ReputationResult result)
    {
        Assert.False(result.IsKnown);
        Assert.False(result.IsMalicious);
        Assert.Equal(0, result.DetectionCount);
        Assert.Equal(0, result.Severity);
        Assert.Null(result.ThreatName);
    }

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
    };

    private sealed class RecordingHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responseFactory) : HttpMessageHandler
    {
        internal int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return responseFactory(request, cancellationToken);
        }
    }

    private sealed class CountingPaddingStream(int byteCount) : Stream
    {
        private int _remaining = byteCount;
        internal int BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = Math.Min(count, _remaining);
            Array.Fill(buffer, (byte)' ', offset, read);
            _remaining -= read;
            BytesRead += read;
            return read;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = Math.Min(buffer.Length, _remaining);
            buffer.Span[..read].Fill((byte)' ');
            _remaining -= read;
            BytesRead += read;
            return ValueTask.FromResult(read);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Read(buffer, offset, count));
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class MemorySettings : ISettingsService
    {
        internal string? ApiKey { get; set; } = "inert-key";
        internal bool Enabled { get; set; } = true;
        internal int WriteCount { get; private set; }

        public T? GetSetting<T>(string key, T defaultValue)
        {
            object? value = key switch
            {
                "MalwareBazaarApiKey" => ApiKey,
                "IsCloudReputationEnabled" => Enabled,
                _ => defaultValue
            };
            return value is T typedValue ? typedValue : defaultValue;
        }

        public void SetSetting<T>(string key, T value) => WriteCount++;
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
