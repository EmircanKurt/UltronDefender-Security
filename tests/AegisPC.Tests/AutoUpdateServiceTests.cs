using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using AegisPC.Service.Update;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Tests signed updates using ephemeral keys, fake HTTP and isolated local directories.</summary>
public sealed class AutoUpdateServiceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "AegisSignedUpdate_" + Guid.NewGuid().ToString("N"));
    private readonly RSA _key = RSA.Create(3072);
    private readonly byte[] _payload = Encoding.UTF8.GetBytes("harmless release fixture");
    private readonly HttpClient _http;
    private readonly AutoUpdateService _service;

    public AutoUpdateServiceTests()
    {
        Directory.CreateDirectory(_root);
        _http = new HttpClient(new PayloadHandler(_payload));
        _service = new AutoUpdateService(_http, trustedManifestPublicKeyPem: _key.ExportSubjectPublicKeyInfoPem(),
            installedVersion: new Version(1, 0, 0), updateBaseDirectory: Path.Combine(_root, "updates"));
    }

    private UpdateManifest Manifest()
    {
        var manifest = new UpdateManifest { Version = "2.0.0", DownloadUrl = "https://updates.invalid/payload.bin",
            SHA256 = Convert.ToHexString(SHA256.HashData(_payload)), PackageSize = _payload.Length,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1), ReleaseDate = DateTime.UtcNow };
        Sign(manifest);
        return manifest;
    }

    private void Sign(UpdateManifest manifest) => manifest.ManifestSignature = Convert.ToBase64String(
        _key.SignData(UpdateManifestVerifier.GetSigningPayload(manifest), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

    [Fact]
    public async Task SignedPackageAppliesAndRollbackRestoresOnlyItsTarget()
    {
        string target = Directory.CreateDirectory(Path.Combine(_root, "app")).FullName;
        string file = Path.Combine(target, "payload.bin");
        await File.WriteAllTextAsync(file, "original");
        string staged = await _service.DownloadAndVerifyAsync(Manifest());
        Assert.True(await _service.ApplyUpdateAsync(staged, target));
        Assert.Equal(_payload, await File.ReadAllBytesAsync(file));
        Assert.False(await _service.RollbackUpdateAsync(Path.Combine(_root, "other")));
        Assert.True(await _service.RollbackUpdateAsync(target));
        Assert.Equal("original", await File.ReadAllTextAsync(file));
    }

    [Theory]
    [InlineData("version")]
    [InlineData("hash")]
    [InlineData("url")]
    [InlineData("size")]
    [InlineData("product")]
    public async Task ChangedSignedFieldsAreRejectedBeforeWriting(string field)
    {
        var manifest = Manifest();
        switch (field)
        {
            case "version": manifest.Version = "3.0.0"; break;
            case "hash": manifest.SHA256 = new string('A', 64); break;
            case "url": manifest.DownloadUrl = "https://other.invalid/payload.bin"; break;
            case "size": manifest.PackageSize++; break;
            case "product": manifest.Product = "OtherProduct"; break;
        }
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.DownloadAndVerifyAsync(manifest));
        Assert.False(Directory.Exists(Path.Combine(_root, "updates")));
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData(@"C:\outside")]
    [InlineData("0.9.0")]
    public async Task InvalidOrOldVersionIsRejectedEvenWhenSigned(string version)
    {
        var manifest = Manifest();
        manifest.Version = version;
        Sign(manifest);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.DownloadAndVerifyAsync(manifest));
    }

    [Fact]
    public async Task ExpiredSignedManifestIsRejected()
    {
        var manifest = Manifest();
        manifest.ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1);
        Sign(manifest);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.DownloadAndVerifyAsync(manifest));
    }

    [Fact]
    public async Task ChangedStagedBytesDoNotOverwriteInstalledFile()
    {
        var staged = await _service.DownloadAndVerifyAsync(Manifest());
        await File.WriteAllTextAsync(staged, new string('X', _payload.Length));
        string target = Directory.CreateDirectory(Path.Combine(_root, "app")).FullName;
        await File.WriteAllTextAsync(Path.Combine(target, "payload.bin"), "original");
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.ApplyUpdateAsync(staged, target));
        Assert.Equal("original", await File.ReadAllTextAsync(Path.Combine(target, "payload.bin")));
    }

    [Fact]
    public async Task OversizedResponseIsRejectedAndPartialFileRemoved()
    {
        var manifest = Manifest();
        manifest.PackageSize--;
        Sign(manifest);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.DownloadAndVerifyAsync(manifest));
        Assert.Empty(Directory.GetFiles(_root, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task PackageSignedByAnotherKeyIsRejected()
    {
        using var otherKey = RSA.Create(3072);
        var manifest = Manifest();
        manifest.ManifestSignature = Convert.ToBase64String(otherKey.SignData(
            UpdateManifestVerifier.GetSigningPayload(manifest), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.DownloadAndVerifyAsync(manifest));
    }

    [Fact]
    public async Task MissingPinnedKeyRejectsAllExtensions()
    {
        using var http = new HttpClient(new PayloadHandler(_payload));
        var updater = new AutoUpdateService(http, updateBaseDirectory: Path.Combine(_root, "disabled"));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => updater.DownloadAndVerifyAsync(Manifest()));
        Assert.False(Directory.Exists(Path.Combine(_root, "disabled")));
    }

    [Fact]
    public async Task PlainHttpAndCancellationAreRejected()
    {
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.CheckForUpdatesAsync("http://updates.invalid/manifest"));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => _service.CheckForUpdatesAsync("https://updates.invalid/manifest", cts.Token));
    }

    [Fact]
    public async Task AppliedReleaseCannotBeReplayed()
    {
        var first = await _service.DownloadAndVerifyAsync(Manifest());
        var second = await _service.DownloadAndVerifyAsync(Manifest());
        string target = Path.Combine(_root, "app");
        Assert.True(await _service.ApplyUpdateAsync(first, target));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => _service.ApplyUpdateAsync(second, target));
    }

    private sealed class PayloadHandler(byte[] payload) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new ByteArrayContent(payload), RequestMessage = request });
    }

    public void Dispose()
    {
        _http.Dispose();
        _key.Dispose();
        Directory.Delete(_root, true);
    }
}
