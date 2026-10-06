using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using AegisPC.ServiceContracts;
using AegisPC.ServiceContracts.IpcMessages;

namespace AegisPC.App.Services;

/// <summary>UI facade; never opens, decrypts or mutates the machine quarantine vault locally.</summary>
public sealed class ServiceQuarantineClient(IServiceIpcClient ipc) : IQuarantineService
{
    /// <inheritdoc />
    public string? LastError { get; private set; }
    /// <inheritdoc />
    public event Action<QuarantineEntry>? OnFileQuarantined;
    /// <inheritdoc />
    public event Action<int>? OnFileRestored;
    /// <inheritdoc />
    public event Action<int>? OnFileDeleted;

    /// <inheritdoc />
    public async Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default)
    {
        // UI explanation is not evidence: the service must re-inspect the candidate.
        var reply = await SendAsync(ServiceCommandType.QuarantineFile, new() { Path = path }, cancellationToken);
        if (reply?.Success != true) return false;
        // A malformed optional notification must not change an already committed operation result.
        try
        {
            var entry = reply.Payload == null ? null : JsonSerializer.Deserialize<QuarantineEntry>(reply.Payload);
            if (entry != null) NotifyObservers(OnFileQuarantined, entry);
        }
        catch (JsonException exception) { System.Diagnostics.Debug.WriteLine("Optional quarantine entry response is malformed: " + exception.Message); }
        return true;
    }

    /// <inheritdoc />
    public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default) => RestoreFileAsync(id, null, cancellationToken);
    /// <inheritdoc />
    public async Task<bool> RestoreFileAsync(int id, string? customDestinationPath, CancellationToken cancellationToken = default)
    {
        var reply = await SendAsync(ServiceCommandType.RestoreQuarantine, new() { Id = id, Destination = customDestinationPath }, cancellationToken);
        if (reply?.Success != true) return false;
        NotifyObservers(OnFileRestored, id); return true;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
    {
        var reply = await SendAsync(ServiceCommandType.DeleteQuarantine, new() { Id = id }, cancellationToken);
        if (reply?.Success != true) return false;
        NotifyObservers(OnFileDeleted, id); return true;
    }

    /// <inheritdoc />
    public async Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default)
    {
        var items = new List<QuarantineEntry>();
        int cursor = 0;
        do
        {
            var reply = await SendAsync(ServiceCommandType.GetQuarantine, new() { AfterId = cursor }, cancellationToken);
            if (reply?.Success != true || reply.Payload == null) throw new IOException(LastError ?? "Quarantine service is unavailable.");
            var page = JsonSerializer.Deserialize<QuarantinePage>(reply.Payload) ?? throw new InvalidDataException("Missing quarantine page.");
            items.AddRange(page.Entries);
            if (page.NextAfterId == null) return items;
            if (page.NextAfterId <= cursor) throw new InvalidDataException("Invalid quarantine page cursor.");
            cursor = page.NextAfterId.Value;
        } while (!cancellationToken.IsCancellationRequested);
        cancellationToken.ThrowIfCancellationRequested();
        return items;
    }

    /// <inheritdoc />
    public async Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var reply = await SendAsync(ServiceCommandType.GetQuarantineItem, new() { Id = id }, cancellationToken);
        return reply?.Success == true && reply.Payload != null ? JsonSerializer.Deserialize<QuarantineEntry>(reply.Payload) : null;
    }

    private async Task<ServiceReply?> SendAsync(ServiceCommandType command, AuthorizedVaultRequest request, CancellationToken ct)
    {
        LastError = null;
        try
        {
            if (!ipc.IsConnected) throw new IOException("Koruma hizmeti bağlı değil; kasa işlemi gerçekleştirilmedi.");
            if (ipc is not IServiceRequestClient transport) throw new IOException("This service client does not support authorized vault operations.");
            var reply = await transport.RequestAsync(command, JsonSerializer.Serialize(request), ct);
            if (!reply.Success) LastError = reply.Code == "CallerContextTokenUnavailable"
                ? "Kullanıcı yetkisiyle dosya işlemi henüz doğrulanmadı; işlem yapılmadı. SYSTEM yetkisine yükseltilmedi."
                : reply.Code;
            return reply;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception exception) { LastError = exception.Message; return null; }
    }

    private static void NotifyObservers<T>(Action<T>? handlers, T value)
    {
        if (handlers == null) return;
        foreach (Action<T> handler in handlers.GetInvocationList())
        {
            try { handler(value); }
            catch (Exception exception) { System.Diagnostics.Debug.WriteLine("Quarantine observer failed: " + exception.GetType().Name); }
        }
    }
}
