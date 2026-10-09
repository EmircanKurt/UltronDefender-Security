using System.Net.Http;
using AegisPC.Contracts.Services;
using AegisPC.Infrastructure.Configuration;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Inert compatibility guards for the removed endpoint name-based feed classifier and local-only updater.</summary>
public sealed class LegacyFeedApiSurfaceReviewTests
{
    /// <summary>Provider family/name strings must not be promoted to endpoint detection classifications.</summary>
    [Fact]
    public void EndpointDoesNotExposeFamilyLabelAsDetection() =>
        Assert.Null(typeof(ThreatFeedUpdater).GetMethod("DetectCategory",
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static));

    /// <summary>Force/bootstrap cannot read credentials or send network requests through the legacy endpoint adapter.</summary>
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task LegacyUpdaterRemainsLocalOnly(bool force, bool bootstrap)
    {
        using var handler = new RejectNetworkHandler();
        using var client = new HttpClient(handler);
        var settings = new RejectSettings();
        var updater = new ThreatFeedUpdater(client, settings);
        Assert.Equal(0, await updater.UpdateFromMalwareBazaarAsync(force, bootstrap));
        Assert.Equal(0, handler.Requests);
        Assert.Equal(0, settings.Reads);
    }

    /// <summary>Cancellation remains observable, rather than being falsely reported as a successful zero-import update.</summary>
    [Fact]
    public async Task LegacyUpdaterPropagatesCancellation()
    {
        var updater = new ThreatFeedUpdater();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            updater.UpdateFromMalwareBazaarAsync(cancellationToken: new CancellationToken(true)));
    }

    private sealed class RejectNetworkHandler : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            throw new InvalidOperationException("An endpoint compatibility test must never send network requests.");
        }
    }

    private sealed class RejectSettings : ISettingsService
    {
        internal int Reads { get; private set; }
        /// <summary>Rejects any credential/configuration read by the compatibility endpoint.</summary>
        public AppSettings Current { get { Reads++; throw new InvalidOperationException("Credential reads are forbidden."); } }
        /// <summary>Rejects general settings reads by this isolated boundary fixture.</summary>
        public T GetSetting<T>(string key, T defaultValue) { Reads++; throw new InvalidOperationException("Settings reads are forbidden."); }
        /// <summary>Rejects settings mutations by this isolated boundary fixture.</summary>
        public void SetSetting<T>(string key, T value) => throw new InvalidOperationException("Settings writes are forbidden.");
        /// <summary>Rejects persistent writes; the test never uses the real settings service.</summary>
        public Task SaveAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException("Persistent writes are forbidden.");
        /// <summary>Rejects persistent reads; the test never uses the real settings service.</summary>
        public Task LoadAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException("Persistent reads are forbidden.");
    }
}
