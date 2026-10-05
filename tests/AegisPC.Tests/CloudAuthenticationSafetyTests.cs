using System.Net;
using System.Net.Http;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.Security.Reputation;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Local-only edition privacy regression. HTTP fixtures cannot receive endpoint hashes even with legacy opt-in.</summary>
public sealed class CloudAuthenticationSafetyTests
{
    private sealed class NoNetwork : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("Local-only endpoint must never query a provider."); }
    }
    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("inert-key")] [InlineData("bad\r\nheader")]
    public async Task LegacyOptInAndApiKeyNeverSendEndpointHash(string? key)
    {
        using var handler = new NoNetwork(); using var client = new HttpClient(handler);
        var settings = new MemorySettings(key);
        using var service = new ReputationService(settings, httpClient: client) { IsCloudLookupEnabled = true };
        var result = await service.CheckReputationAsync(new string('A', 64));
        Assert.False(service.IsCloudLookupEnabled); Assert.False(result.IsKnown); Assert.False(result.IsMalicious);
        Assert.Equal(0, handler.Calls); Assert.Equal(0, service.CacheCount); Assert.Equal(0, settings.Writes);
        var updater = new ThreatFeedUpdater(client, settings);
        Assert.Equal(0, await updater.UpdateFromMalwareBazaarAsync(force: true));
        Assert.Equal(0, handler.Calls); Assert.Equal(0, settings.Writes);
    }
    [Fact]
    public async Task LocalTestMarkerRemainsAvailableWithoutCloudAndDoesNotWritePayload()
    {
        using var handler = new NoNetwork(); using var client = new HttpClient(handler);
        using var service = new ReputationService(httpClient: client);
        var result = await service.CheckReputationAsync("275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F");
        Assert.True(result.IsKnown); Assert.True(result.IsMalicious); Assert.Equal("TestMalware", result.MalwareFamily);
        Assert.Equal(0, handler.Calls);
    }
    [Fact]
    public async Task CallerCancellationPropagatesBeforeAnyLocalResult()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        using var service = new ReputationService();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.CheckReputationAsync("", cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ThreatFeedUpdater().UpdateFromMalwareBazaarAsync(cancellationToken: cts.Token));
    }
    private sealed class MemorySettings(string? key) : ISettingsService
    {
        public int Writes;
        public T? GetSetting<T>(string name, T defaultValue)
        {
            object? value = name == "MalwareBazaarApiKey" ? key : name == "IsCloudReputationEnabled" ? true : defaultValue;
            return value is T typed ? typed : defaultValue;
        }
        public void SetSetting<T>(string name, T value) => Writes++;
        public Task SaveAsync(CancellationToken ct = default) => Task.CompletedTask;
        public Task LoadAsync(CancellationToken ct = default) => Task.CompletedTask;
    }
}

