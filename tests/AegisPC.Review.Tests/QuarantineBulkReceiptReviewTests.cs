using System.IO;
using AegisPC.App.ViewModels;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using Xunit;

namespace AegisPC.Review.Tests;

/// <summary>Inert recovery-receipt regressions; no disk, native quarantine, installed service or Windows setting is accessed.</summary>
public sealed class QuarantineBulkReceiptReviewTests
{
    /// <summary>A failed or unacknowledged restore retains recovery content and cannot create permanent trust or deletion.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedRestoreRetainsEntryAndEvidenceWithoutDeletingOrTrusting(bool throws)
    {
        var entry = Entry(1);
        var vault = new FakeVault([entry], new() { [1] = throws ? Outcome.Throws : Outcome.Failure });
        var evidence = new FakeFindings(entry.OriginalPath);
        var allowlist = new FakeAllowlist();
        var settings = new FakeSettings();
        var toast = new FakeToast();
        var vm = new QuarantineViewModel(quarantineService: vault, findingService: evidence,
            allowlistService: allowlist, settingsService: settings, toastService: toast);

        await vm.RemoveAllFromQuarantineAsync();

        Assert.Equal([1], vault.RestoreRequests);
        Assert.Equal(0, vault.DeleteRequests);
        Assert.Same(entry, Assert.Single(vm.QuarantinedItems));
        Assert.Equal(QuarantineStatus.Quarantined, entry.Status);
        AssertEvidenceUntouched(evidence, allowlist, settings);
        Assert.Contains(vm.Incidents, incident => incident.IncidentId.StartsWith("FIND-", StringComparison.Ordinal));
        Assert.Contains("0 dosyanın geri yüklenmesi doğrulandı; 1 dosyanın geri yüklenmesi doğrulanamadı", vm.StatusMessage);
        Assert.Equal("Warning", toast.LastType);
        Assert.False(vm.IsLoading);
    }

    /// <summary>Only positive service receipts contribute to success; a later exception does not stop remaining recoveries.</summary>
    [Fact]
    public async Task MixedReceiptsCountOnlyConfirmedRestoresAndKeepUnconfirmedEntries()
    {
        var entries = new[] { Entry(1), Entry(2), Entry(3), Entry(4) };
        var vault = new FakeVault(entries, new()
            { [1] = Outcome.Success, [2] = Outcome.Throws, [3] = Outcome.Failure, [4] = Outcome.Success });
        var evidence = new FakeFindings(entries[0].OriginalPath);
        var allowlist = new FakeAllowlist();
        var settings = new FakeSettings();
        var toast = new FakeToast();
        var vm = new QuarantineViewModel(quarantineService: vault, findingService: evidence,
            allowlistService: allowlist, settingsService: settings, toastService: toast);

        await vm.RemoveAllFromQuarantineAsync();

        Assert.Equal([1, 2, 3, 4], vault.RestoreRequests);
        Assert.Equal([2, 3], vm.QuarantinedItems.Select(item => item.Id));
        Assert.Equal(0, vault.DeleteRequests);
        AssertEvidenceUntouched(evidence, allowlist, settings);
        Assert.Contains("2 dosyanın geri yüklenmesi doğrulandı; 2 dosyanın geri yüklenmesi doğrulanamadı", vm.StatusMessage);
        Assert.DoesNotContain("Tüm değişiklikler kaydedildi", vm.StatusMessage);
        Assert.Equal("Warning", toast.LastType);
        Assert.False(vm.IsLoading);
    }

    /// <summary>Even confirmed recovery is not consent to persist an allowlist entry, resolve path-matched evidence or dismiss incidents.</summary>
    [Fact]
    public async Task ConfirmedRestoreDoesNotGrantTrustOrResolveIndependentFinding()
    {
        var entry = Entry(1);
        var vault = new FakeVault([entry], new() { [1] = Outcome.Success });
        var evidence = new FakeFindings(entry.OriginalPath);
        var allowlist = new FakeAllowlist();
        var settings = new FakeSettings();
        var toast = new FakeToast();
        var vm = new QuarantineViewModel(quarantineService: vault, findingService: evidence,
            allowlistService: allowlist, settingsService: settings, toastService: toast);

        await vm.RemoveAllFromQuarantineAsync();

        Assert.Empty(vm.QuarantinedItems);
        Assert.Equal(0, vault.DeleteRequests);
        AssertEvidenceUntouched(evidence, allowlist, settings);
        Assert.Contains(vm.Incidents, incident => incident.IncidentId.StartsWith("FIND-", StringComparison.Ordinal));
        Assert.Contains("1 dosyanın geri yüklenmesi doğrulandı; 0 dosyanın geri yüklenmesi doğrulanamadı", vm.StatusMessage);
        Assert.Equal("Success", toast.LastType);
        Assert.False(vm.IsLoading);
    }

    /// <summary>An explicit successful delete removes vault content without creating any allowlist or finding trust.</summary>
    [Fact]
    public async Task ExplicitDeleteDoesNotGrantTrust()
    {
        var entry = Entry(1);
        var vault = new FakeVault([entry], new());
        var evidence = new FakeFindings(entry.OriginalPath);
        var allowlist = new FakeAllowlist();
        var settings = new FakeSettings();
        var vm = new QuarantineViewModel(quarantineService: vault, findingService: evidence,
            allowlistService: allowlist, settingsService: settings);

        await vm.DeleteItemAsync(entry);

        Assert.Equal(1, vault.DeleteRequests);
        Assert.Empty(vault.RestoreRequests);
        Assert.Empty(vm.QuarantinedItems);
        AssertEvidenceUntouched(evidence, allowlist, settings);
        Assert.Contains("diskten kalıcı olarak silindi", vm.StatusMessage);
        Assert.False(vm.IsLoading);
    }

    /// <summary>Single recovery failures retain their explanation after data refresh and clear busy state even when the provider throws.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SingleRestoreFailureSurvivesRefreshAndClearsBusyState(bool throws)
    {
        var entry = Entry(1);
        var vault = new FakeVault([entry], new() { [1] = throws ? Outcome.Throws : Outcome.Failure });
        var toast = new FakeToast();
        var vm = new QuarantineViewModel(quarantineService: vault, toastService: toast);

        await vm.RestoreItemAsync(entry);

        Assert.Equal([1], vault.RestoreRequests);
        Assert.Equal(0, vault.DeleteRequests);
        Assert.Same(entry, Assert.Single(vm.QuarantinedItems));
        Assert.StartsWith("Geri yükleme başarısız:", vm.StatusMessage);
        Assert.Contains(throws ? "Inert acknowledgement loss" : "CallerContextTokenUnavailable", vm.StatusMessage);
        Assert.Equal("Warning", toast.LastType);
        Assert.False(vm.IsLoading);
    }

    /// <summary>Single deletion failures remain failures after refresh; a throwing provider cannot leave the command busy.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SingleDeleteFailureSurvivesRefreshAndClearsBusyState(bool throws)
    {
        var entry = Entry(1);
        var vault = new FakeVault([entry], new()) { DeleteOutcome = throws ? Outcome.Throws : Outcome.Failure };
        var toast = new FakeToast();
        var vm = new QuarantineViewModel(quarantineService: vault, toastService: toast);

        await vm.DeleteItemAsync(entry);

        Assert.Equal(1, vault.DeleteRequests);
        Assert.Empty(vault.RestoreRequests);
        Assert.Same(entry, Assert.Single(vm.QuarantinedItems));
        Assert.StartsWith("Silme işlemi başarısız:", vm.StatusMessage);
        Assert.Contains(throws ? "Inert deletion acknowledgement loss" : "CallerContextTokenUnavailable", vm.StatusMessage);
        Assert.Equal("Warning", toast.LastType);
        Assert.False(vm.IsLoading);
    }

    /// <summary>A confirmed single recovery keeps its receipt visible after refreshing an empty vault.</summary>
    [Fact]
    public async Task SingleRestoreSuccessSurvivesRefresh()
    {
        var entry = Entry(1);
        var vault = new FakeVault([entry], new() { [1] = Outcome.Success });
        var toast = new FakeToast();
        var vm = new QuarantineViewModel(quarantineService: vault, toastService: toast);

        await vm.RestoreItemAsync(entry);

        Assert.Empty(vm.QuarantinedItems);
        Assert.Equal(0, vault.DeleteRequests);
        Assert.Contains("orijinal konumuna", vm.StatusMessage);
        Assert.Contains("geri yüklendi", vm.StatusMessage);
        Assert.Equal("Success", toast.LastType);
        Assert.False(vm.IsLoading);
    }

    private static void AssertEvidenceUntouched(FakeFindings evidence, FakeAllowlist allowlist, FakeSettings settings)
    {
        Assert.Equal(FindingStatus.Active, evidence.Finding.Status);
        Assert.False(evidence.Finding.IsAllowlisted);
        Assert.Equal(0, evidence.UpdateRequests);
        Assert.Equal(0, allowlist.AddRequests);
        Assert.Equal(0, settings.Writes);
    }

    private static QuarantineEntry Entry(int id) => new()
    { Id = id, FileName = $"inert-{id}.bin", OriginalPath = $"C:\\inert-fixture\\{id}.bin", SHA256 = new string('A', 64) };

    private enum Outcome { Success, Failure, Throws }

    private sealed class FakeVault(IEnumerable<QuarantineEntry> initial, Dictionary<int, Outcome> outcomes) : IQuarantineService
    {
        private readonly List<QuarantineEntry> _entries = initial.ToList();
        internal List<int> RestoreRequests { get; } = [];
        internal int DeleteRequests { get; private set; }
        internal Outcome DeleteOutcome { get; init; } = Outcome.Success;
        public string? LastError => "CallerContextTokenUnavailable";
        public event Action<QuarantineEntry>? OnFileQuarantined { add { } remove { } }
        public event Action<int>? OnFileRestored { add { } remove { } }
        public event Action<int>? OnFileDeleted { add { } remove { } }
        public Task<bool> RestoreFileAsync(int id, CancellationToken cancellationToken = default)
        {
            RestoreRequests.Add(id);
            if (outcomes[id] == Outcome.Throws) return Task.FromException<bool>(new IOException("Inert acknowledgement loss"));
            bool succeeded = outcomes[id] == Outcome.Success;
            if (succeeded) _entries.RemoveAll(entry => entry.Id == id);
            return Task.FromResult(succeeded);
        }
        public Task<bool> RestoreFileAsync(int id, string? destination, CancellationToken cancellationToken = default) => RestoreFileAsync(id, cancellationToken);
        public Task<bool> DeleteQuarantinedAsync(int id, CancellationToken cancellationToken = default)
        {
            DeleteRequests++;
            if (DeleteOutcome == Outcome.Throws) return Task.FromException<bool>(new IOException("Inert deletion acknowledgement loss"));
            return Task.FromResult(DeleteOutcome == Outcome.Success && _entries.RemoveAll(entry => entry.Id == id) != 0);
        }
        public Task<List<QuarantineEntry>> GetQuarantinedItemsAsync(CancellationToken cancellationToken = default) => Task.FromResult(_entries.ToList());
        public Task<QuarantineEntry?> GetItemByIdAsync(int id, CancellationToken cancellationToken = default) => Task.FromResult(_entries.Find(entry => entry.Id == id));
        public Task<bool> QuarantineFileAsync(string path, string reason, CancellationToken cancellationToken = default) => throw new InvalidOperationException("No new content is authorized by recovery");
    }

    private sealed class FakeFindings(string path) : ISecurityFindingService
    {
        internal SecurityFinding Finding { get; } = new() { ObjectPath = path, Title = "Independent evidence", Status = FindingStatus.Active };
        internal int UpdateRequests { get; private set; }
        public Task<List<SecurityFinding>> GetAllFindingsAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<SecurityFinding> { Finding });
        public Task UpdateFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default) { UpdateRequests++; return Task.CompletedTask; }
        public Task<List<SecurityFinding>> GetFindingsByRiskAsync(RiskLevel risk, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task AddFindingAsync(SecurityFinding finding, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task<SecurityFinding?> GetFindingByIdAsync(Guid id, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task<int> GetActiveCountAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException();
    }

    private sealed class FakeAllowlist : IAllowlistService
    {
        internal int AddRequests { get; private set; }
        public Task AddToAllowlistAsync(AllowlistEntry entry, CancellationToken cancellationToken = default) { AddRequests++; return Task.CompletedTask; }
        public bool IsAllowlisted(string hash) => false;
        public bool IsPathAllowlisted(string path) => false;
        public Task<bool> IsAllowlistedAsync(string hash, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<bool> IsPathAllowlistedAsync(string path, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task RemoveFromAllowlistAsync(int id, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task<List<AllowlistEntry>> GetAllowlistAsync(CancellationToken cancellationToken = default) => Task.FromResult(new List<AllowlistEntry>());
        public Task<bool> CheckHashChangedAsync(AllowlistEntry entry, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
    }

    private sealed class FakeSettings : ISettingsService
    {
        internal int Writes { get; private set; }
        public T? GetSetting<T>(string key, T defaultValue) => defaultValue;
        public void SetSetting<T>(string key, T value) => Writes++;
        public Task SaveAsync(CancellationToken cancellationToken = default) { Writes++; return Task.CompletedTask; }
        public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeToast : IWindowsToastNotificationService
    {
        internal string? LastType { get; private set; }
        public void ShowToast(string title, string message, string type = "Info") => LastType = type;
    }
}
