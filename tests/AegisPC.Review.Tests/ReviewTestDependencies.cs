using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Tests;

// In-memory dependencies for linked quarantine restore fixtures; no OS actions.
internal sealed class TestSettingsService : ISettingsService
{
    private readonly Dictionary<string, object> _settings = new();
    public AegisPC.Infrastructure.Configuration.AppSettings Current { get; } = new();
    public T GetSetting<T>(string key, T defaultValue) =>
        _settings.TryGetValue(key, out var value) && value is T typed ? typed : defaultValue;
    public void SetSetting<T>(string key, T value) { if (value != null) _settings[key] = value; }
    public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
}

internal sealed class FakeToastService : IWindowsToastNotificationService
{
    public List<(string Title, string Message, string Type)> SentToasts { get; } = new();
    public void ShowToast(string title, string message, string type = "Info") => SentToasts.Add((title, message, type));
}

internal sealed class FakeAuditLogService : IAuditLogService
{
    public List<AuditLogEntry> Entries { get; } = new();
    public Task LogActionAsync(AuditAction action, string targetType, string targetName, string? targetPath = null,
        string? details = null, AuditResult result = AuditResult.Success, string? errorMessage = null,
        CancellationToken cancellationToken = default)
    {
        Entries.Add(new AuditLogEntry { Action = action, TargetType = targetType, TargetName = targetName,
            TargetPath = targetPath, Details = details, Result = result });
        return Task.CompletedTask;
    }
    public Task<List<AuditLogEntry>> GetLogsAsync(DateTime? from = null, DateTime? to = null,
        CancellationToken cancellationToken = default) => Task.FromResult(Entries);
    public Task ClearLogsAsync(CancellationToken cancellationToken = default)
    { Entries.Clear(); return Task.CompletedTask; }
}
