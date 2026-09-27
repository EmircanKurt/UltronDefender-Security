using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Service.Update;

public interface IAutoUpdateService
{
    Task<UpdateManifest?> CheckForUpdatesAsync(string manifestUrl, CancellationToken ct = default);
    Task<string> DownloadAndVerifyAsync(UpdateManifest manifest, IProgress<double>? progress = null, CancellationToken ct = default);
    Task<bool> ApplyUpdateAsync(string stagedPackagePath, string targetDirectory, CancellationToken ct = default);
    Task<bool> RollbackUpdateAsync(string targetDirectory, CancellationToken ct = default);
}

/// <summary>Stages signed releases and applies only packages authenticated by this service instance.
/// Restarting requires re-downloading metadata/packages. Missing release keys disable updates.</summary>
public class AutoUpdateService : IAutoUpdateService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<AutoUpdateService>? _logger;
    private readonly UpdateManifestVerifier _verifier;
    private readonly string _baseDirectory;
    private readonly SemaphoreSlim _operations = new(1, 1);
    private readonly ConcurrentDictionary<string, Receipt> _receipts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Backup> _backups = new(StringComparer.OrdinalIgnoreCase);
    private Version _installedVersion;
    private sealed record Receipt(string Hash, long Size, string FileName, Version Version, DateTimeOffset ExpiresUtc);
    private sealed record Backup(string Destination, string Path, string Hash);

    public static readonly string DefaultUpdateBaseDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "UltronDefender", "Updates");
    public static readonly string StagingDirectory = Path.Combine(DefaultUpdateBaseDir, "staging");
    public static readonly string BackupDirectory = Path.Combine(DefaultUpdateBaseDir, "backup");

    /// <summary>Uses a pinned release key and installed version supplied by trusted deployment.
    /// A custom base directory isolates tests; it does not change trust requirements.</summary>
    public AutoUpdateService(HttpClient? httpClient = null, ILogger<AutoUpdateService>? logger = null,
        string? trustedManifestPublicKeyPem = null, Version? installedVersion = null, string? updateBaseDirectory = null)
    {
        _httpClient = httpClient ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            { Timeout = TimeSpan.FromSeconds(60) };
        _logger = logger;
        _installedVersion = installedVersion ?? typeof(AutoUpdateService).Assembly.GetName().Version ?? new Version(0, 0);
        _verifier = new UpdateManifestVerifier(trustedManifestPublicKeyPem, _installedVersion);
        _baseDirectory = Path.GetFullPath(updateBaseDirectory ?? DefaultUpdateBaseDir);
    }

    /// <summary>Fetches bounded HTTPS metadata and authenticates its release signature. Cancellation propagates.</summary>
    public async Task<UpdateManifest?> CheckForUpdatesAsync(string manifestUrl, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var uri = UpdateManifestVerifier.RequireHttps(manifestUrl);
        try
        {
            using var response = await _httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
            ValidateResponse(response);
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            using var buffer = new MemoryStream();
            await CopyBoundedAsync(input, buffer, 64 * 1024, null, ct);
            var manifest = JsonSerializer.Deserialize<UpdateManifest>(buffer.ToArray(),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (manifest is null) throw new CryptographicException("Empty release manifest.");
            _verifier.Verify(manifest);
            return manifest;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or CryptographicException)
        {
            _logger?.LogWarning(ex, "Release metadata rejected.");
            return null;
        }
    }

    /// <summary>Downloads a signed, size-bounded package into a unique directory; failed downloads are removed.</summary>
    public async Task<string> DownloadAndVerifyAsync(UpdateManifest manifest, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        // Snapshot mutable caller-owned metadata before verification or the first await.
        var snapshot = JsonSerializer.Deserialize<UpdateManifest>(JsonSerializer.Serialize(manifest))
            ?? throw new CryptographicException("Missing release manifest.");
        _verifier.Verify(snapshot);
        var uri = UpdateManifestVerifier.RequireHttps(snapshot.DownloadUrl);
        string fileName = Path.GetFileName(uri.LocalPath);
        if (string.IsNullOrWhiteSpace(fileName) || fileName is "." or ".." ||
            fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new CryptographicException("Invalid package filename.");
        string directory = Path.Combine(_baseDirectory, "staging", Guid.NewGuid().ToString("N"));
        RejectReparsePoints(directory);
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, fileName);
        try
        {
            using var response = await _httpClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
            ValidateResponse(response);
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 81920, true);
            await CopyBoundedAsync(input, output, snapshot.PackageSize, progress, ct);
            if (output.Length != snapshot.PackageSize) throw new CryptographicException("Package length mismatch.");
            output.Position = 0;
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(output, ct));
            if (!string.Equals(hash, snapshot.SHA256, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("Package digest mismatch.");
            _receipts[path] = new Receipt(hash, output.Length, fileName, Version.Parse(snapshot.Version), snapshot.ExpiresUtc);
            return path;
        }
        catch
        {
            TryDelete(path);
            throw;
        }
    }

    /// <summary>Applies only an authenticated package, rechecking its bytes under the same read lock used for copying.</summary>
    public async Task<bool> ApplyUpdateAsync(string stagedPackagePath, string targetDirectory, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        string source = Path.GetFullPath(stagedPackagePath);
        if (!_receipts.TryGetValue(source, out var receipt))
            throw new CryptographicException("Package was not authenticated by this updater.");
        await _operations.WaitAsync(ct);
        string? temporary = null;
        try
        {
            if (receipt.ExpiresUtc <= DateTimeOffset.UtcNow) throw new CryptographicException("Staged release authorization expired.");
            if (receipt.Version <= _installedVersion) throw new CryptographicException("Release downgrade or replay rejected.");
            RejectReparsePoints(source);
            string target = Path.GetFullPath(targetDirectory);
            RejectReparsePoints(target);
            await using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
            if (input.Length != receipt.Size ||
                !string.Equals(Convert.ToHexString(await SHA256.HashDataAsync(input, ct)), receipt.Hash, StringComparison.Ordinal))
                throw new CryptographicException("Staged package changed after authentication.");
            input.Position = 0;
            Directory.CreateDirectory(target);
            string destination = Path.Combine(target, receipt.FileName);
            RejectReparsePoints(destination);
            temporary = Path.Combine(target, "." + Guid.NewGuid().ToString("N") + ".update");
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true))
            {
                await input.CopyToAsync(output, ct);
                await output.FlushAsync(ct);
                output.Flush(true);
            }
            Backup? backup = null;
            if (File.Exists(destination))
            {
                string backupDir = Path.Combine(_baseDirectory, "backup", Guid.NewGuid().ToString("N"));
                RejectReparsePoints(backupDir);
                Directory.CreateDirectory(backupDir);
                string backupPath = Path.Combine(backupDir, receipt.FileName);
                await using var original = new FileStream(destination, FileMode.Open, FileAccess.Read, FileShare.Read);
                await using var copy = new FileStream(backupPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
                await original.CopyToAsync(copy, ct);
                copy.Position = 0;
                backup = new Backup(destination, backupPath, Convert.ToHexString(await SHA256.HashDataAsync(copy, ct)));
            }
            ct.ThrowIfCancellationRequested();
            File.Move(temporary, destination, overwrite: true);
            temporary = null;
            if (backup is not null) _backups[target] = backup;
            else _backups.TryRemove(target, out _);
            _installedVersion = receipt.Version;
            _receipts.TryRemove(source, out _);
            return true;
        }
        finally
        {
            if (temporary is not null) TryDelete(temporary);
            _operations.Release();
        }
    }

    /// <summary>Restores only this instance's last backup for the exact target after checking its recorded digest.</summary>
    public async Task<bool> RollbackUpdateAsync(string targetDirectory, CancellationToken ct = default)
    {
        await _operations.WaitAsync(ct);
        string? temporary = null;
        try
        {
            string target = Path.GetFullPath(targetDirectory);
            if (!_backups.TryGetValue(target, out var backup)) return false;
            RejectReparsePoints(backup.Path);
            RejectReparsePoints(backup.Destination);
            await using var input = new FileStream(backup.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (Convert.ToHexString(await SHA256.HashDataAsync(input, ct)) != backup.Hash)
                throw new CryptographicException("Rollback backup was modified.");
            input.Position = 0;
            temporary = Path.Combine(target, "." + Guid.NewGuid().ToString("N") + ".rollback");
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await input.CopyToAsync(output, ct);
                output.Flush(true);
            }
            ct.ThrowIfCancellationRequested();
            File.Move(temporary, backup.Destination, overwrite: true);
            temporary = null;
            _backups.TryRemove(target, out _);
            return true;
        }
        finally
        {
            if (temporary is not null) TryDelete(temporary);
            _operations.Release();
        }
    }

    private static void ValidateResponse(HttpResponseMessage response)
    {
        response.EnsureSuccessStatusCode();
        if ((int)response.StatusCode >= 300) throw new HttpRequestException("Update redirects are not accepted.");
        if (response.RequestMessage?.RequestUri is { } finalUri) UpdateManifestVerifier.RequireHttps(finalUri.AbsoluteUri);
    }

    private static async Task CopyBoundedAsync(Stream input, Stream output, long limit, IProgress<double>? progress, CancellationToken ct)
    {
        var buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await input.ReadAsync(buffer, ct)) != 0)
        {
            total += read;
            if (total > limit) throw new CryptographicException("Update response exceeds its size limit.");
            await output.WriteAsync(buffer.AsMemory(0, read), ct);
            progress?.Report((double)total / limit);
        }
    }

    private static void RejectReparsePoints(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Update paths must not traverse reparse points.");
    }

    private void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { _logger?.LogWarning(ex, "Unable to remove temporary update file {Path}", path); }
    }
}
