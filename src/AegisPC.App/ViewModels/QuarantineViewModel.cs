using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class QuarantineViewModel : ObservableObject
    {
        private readonly IQuarantineService? _quarantineService;
        private readonly IBehaviorEngine? _behaviorEngine;
        private readonly ISecurityFindingService? _findingService;
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly IWindowsToastNotificationService? _toastService;
        private readonly ISettingsService? _settingsService;
        private readonly IAllowlistService? _allowlistService;
        private readonly HashSet<string> _dismissedIncidentIds = new(StringComparer.OrdinalIgnoreCase);

        [ObservableProperty]
        private string pageTitle = "Karantina & Olaylar";

        // Tab state
        [ObservableProperty]
        private bool isQuarantineTabActive = true;

        [ObservableProperty]
        private bool isIncidentsTabActive = false;

        partial void OnIsQuarantineTabActiveChanged(bool value)
        {
            if (value && IsIncidentsTabActive)
            {
                IsIncidentsTabActive = false;
            }
            else if (!value && !IsIncidentsTabActive)
            {
                IsIncidentsTabActive = true;
            }
        }

        partial void OnIsIncidentsTabActiveChanged(bool value)
        {
            if (value && IsQuarantineTabActive)
            {
                IsQuarantineTabActive = false;
            }
            else if (!value && !IsQuarantineTabActive)
            {
                IsQuarantineTabActive = true;
            }
        }

        // Quarantine Vault Tab
        [ObservableProperty]
        private ObservableCollection<QuarantineEntry> quarantinedItems = new();

        [ObservableProperty]
        private QuarantineEntry? selectedItem;

        [ObservableProperty]
        private bool hasNoQuarantinedItems;

        [ObservableProperty]
        private string vaultCountText = "Durum alınmadı";

        [ObservableProperty]
        private bool canRemoveAll;

        // Incident Center Tab
        [ObservableProperty]
        private ObservableCollection<SecurityIncident> incidents = new();

        [ObservableProperty]
        private SecurityIncident? selectedIncident;

        [ObservableProperty]
        private bool hasNoIncidents = true;

        [ObservableProperty]
        private int activeIncidentCount = 0;

        // Common State
        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public static QuarantineViewModel? Current { get; private set; }

        public QuarantineViewModel(
            IQuarantineService? quarantineService = null,
            IBehaviorEngine? behaviorEngine = null,
            ISecurityFindingService? findingService = null,
            IScanCoordinatorService? scanCoordinator = null,
            IWindowsToastNotificationService? toastService = null,
            ISettingsService? settingsService = null,
            IAllowlistService? allowlistService = null)
        {
            Current = this;
            _quarantineService = quarantineService;
            _behaviorEngine = behaviorEngine;
            _findingService = findingService;
            _scanCoordinator = scanCoordinator;
            _toastService = toastService;
            _settingsService = settingsService;
            _allowlistService = allowlistService;

            if (_quarantineService != null)
            {
                _quarantineService.OnFileQuarantined += (entry) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        if (!QuarantinedItems.Any(q => q.Id == entry.Id))
                        {
                            QuarantinedItems.Insert(0, entry);
                            HasNoQuarantinedItems = false;
                            CanRemoveAll = true;
                            StatusMessage = $"Karantinada {QuarantinedItems.Count} adet etkisizleştirilmiş dosya bulunuyor.";
                        }
                    });
                };

                _quarantineService.OnFileRestored += (id) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        var item = QuarantinedItems.FirstOrDefault(q => q.Id == id);
                        if (item != null) QuarantinedItems.Remove(item);
                        HasNoQuarantinedItems = QuarantinedItems.Count == 0;
                        CanRemoveAll = QuarantinedItems.Count > 0;
                    });
                };

                _quarantineService.OnFileDeleted += (id) =>
                {
                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        var item = QuarantinedItems.FirstOrDefault(q => q.Id == id);
                        if (item != null) QuarantinedItems.Remove(item);
                        HasNoQuarantinedItems = QuarantinedItems.Count == 0;
                        CanRemoveAll = QuarantinedItems.Count > 0;
                    });
                };
            }

            if (_settingsService != null)
            {
                try
                {
                    var savedDismissed = _settingsService.GetSetting<List<string>>("DismissedIncidentIds", new List<string>());
                    if (savedDismissed != null)
                    {
                        foreach (var id in savedDismissed)
                        {
                            if (!string.IsNullOrWhiteSpace(id))
                            {
                                _dismissedIncidentIds.Add(id);
                            }
                        }
                    }
                }
                catch { }
            }

            if (_behaviorEngine != null)
            {
                _behaviorEngine.OnIncidentCreated += (incident) =>
                {
                    Action action = () =>
                    {
                        if (incident.Status is not ("Reviewed" or "Remediated"))
                        {
                            var previous = Incidents.FirstOrDefault(i => i.IncidentId == incident.IncidentId);
                            bool selected = previous != null && SelectedIncident == previous;
                            if (previous != null) Incidents.Remove(previous);
                            Incidents.Insert(0, incident);
                            if (selected) SelectedIncident = incident;
                            while (Incidents.Count > 100)
                            {
                                Incidents.RemoveAt(Incidents.Count - 1);
                            }
                            HasNoIncidents = Incidents.Count == 0;
                            ActiveIncidentCount = Incidents.Count(i => i.Status is "Active" or "Contained" or "ObservationOnly");
                            if (SelectedIncident == null) SelectedIncident = incident;
                        }
                    };

                    if (Application.Current?.Dispatcher != null && !Application.Current.Dispatcher.CheckAccess())
                    {
                        Application.Current.Dispatcher.InvokeAsync(action);
                    }
                    else
                    {
                        action();
                    }
                };
            }

            if (_scanCoordinator != null)
            {
                _scanCoordinator.ScanCompleted += (result) =>
                {
                    _ = RefreshAllDataAsync();
                };
            }

            _ = RefreshAllDataAsync();
        }

        public void NavigateToTab(bool showIncidentsTab)
        {
            if (showIncidentsTab)
            {
                SelectIncidentsTab();
            }
            else
            {
                if (QuarantinedItems.Count == 0 && Incidents.Count > 0)
                {
                    SelectIncidentsTab();
                }
                else
                {
                    SelectQuarantineTab();
                }
            }

            _ = Task.Run(async () =>
            {
                await RefreshAllDataAsync();
                await (Application.Current?.Dispatcher?.InvokeAsync(() =>
                {
                    if (!showIncidentsTab && QuarantinedItems.Count == 0 && Incidents.Count > 0)
                    {
                        SelectIncidentsTab();
                    }
                })?.Task ?? Task.CompletedTask);
            });
        }

        [RelayCommand]
        public void SelectQuarantineTab()
        {
            IsQuarantineTabActive = true;
            IsIncidentsTabActive = false;
        }

        [RelayCommand]
        public void SelectIncidentsTab()
        {
            IsQuarantineTabActive = false;
            IsIncidentsTabActive = true;
        }

        [RelayCommand]
        public async Task RefreshAllDataAsync()
        {
            await LoadItemsAsync();
            await LoadIncidentsAsync();
            _ = DashboardViewModel.Current?.RefreshThreatStatusAsync();
        }

        [RelayCommand]
        public async Task LoadItemsAsync()
        {
            HasNoQuarantinedItems = false;
            CanRemoveAll = false;
            VaultCountText = "Yükleniyor";
            if (_quarantineService == null)
            {
                VaultCountText = "Kullanılamıyor";
                StatusMessage = "Kasa sahibi hizmete ulaşılamıyor; kasanın boş olduğu doğrulanmadı.";
                return;
            }

            IsLoading = true;
            StatusMessage = "Karantinadaki öğeler yükleniyor...";
            try
            {
                var items = await _quarantineService.GetQuarantinedItemsAsync();
                QuarantinedItems = new ObservableCollection<QuarantineEntry>(items);
                HasNoQuarantinedItems = QuarantinedItems.Count == 0;
                CanRemoveAll = QuarantinedItems.Count > 0;
                VaultCountText = QuarantinedItems.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
                StatusMessage = $"Kasadan {QuarantinedItems.Count} kayıt alındı; bu sayı süreç sonlandırma kanıtı değildir.";
            }
            catch (Exception ex)
            {
                VaultCountText = "Kullanılamıyor";
                HasNoQuarantinedItems = false;
                CanRemoveAll = false;
                Serilog.Log.Warning(ex, "Quarantine snapshot is unavailable; an empty vault is not confirmed.");
                StatusMessage = $"Hata: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }

        [RelayCommand]
        public async Task LoadIncidentsAsync()
        {
            IsLoading = true;
            try
            {
                var combinedList = new List<SecurityIncident>();

                // 1. Load Behavioral Engine Incidents
                if (_behaviorEngine != null)
                {
                    var activeList = await _behaviorEngine.GetActiveIncidentsAsync();
                    if (activeList != null)
                    {
                        foreach (var inc in activeList)
                        {
                            if (inc.Status is not ("Reviewed" or "Remediated"))
                            {
                                combinedList.Add(inc);
                            }
                        }
                    }
                }

                var seenEvidenceIds = new HashSet<string>(combinedList.Select(i => i.IncidentId), StringComparer.OrdinalIgnoreCase);

                // 2. Load Persistent Scan Findings from Database
                if (_findingService != null)
                {
                    var findings = await _findingService.GetAllFindingsAsync();
                    if (findings != null)
                    {
                        foreach (var f in findings)
                        {
                            if (f.Status == FindingStatus.Resolved || f.Status == FindingStatus.Ignored || f.IsAllowlisted)
                            {
                                continue;
                            }


                            var findingRecord = ConvertFindingToIncident(f);
                            if (seenEvidenceIds.Add(findingRecord.IncidentId))
                            {
                                combinedList.Add(findingRecord);
                            }
                        }
                    }
                }

                // 3. Load Current Active Coordinator Findings (Live Scan)
                if (_scanCoordinator?.CurrentFindings != null)
                {
                    foreach (var f in _scanCoordinator.CurrentFindings)
                    {
                        if (f.Status == FindingStatus.Resolved || f.Status == FindingStatus.Ignored || f.IsAllowlisted)
                        {
                            continue;
                        }

                        var findingRecord = ConvertFindingToIncident(f);
                        if (seenEvidenceIds.Add(findingRecord.IncidentId))
                        {
                            combinedList.Add(findingRecord);
                        }
                    }
                }

                // 4. BI-DIRECTIONAL DATA CONSISTENCY: Quarantined files must appear in Incident History
                if (QuarantinedItems != null && QuarantinedItems.Count > 0)
                {
                    foreach (var q in QuarantinedItems)
                    {
                        if (q.Status != QuarantineStatus.Quarantined)
                        {
                            continue;
                        }

                        // Keep evidence and action history separate; pathname equality cannot prove containment.
                        var actionRecord = ConvertQuarantineToIncident(q);
                        if (seenEvidenceIds.Add(actionRecord.IncidentId)) combinedList.Add(actionRecord);
                    }
                }

                // Sort by RiskScore Descending
                var sorted = combinedList.OrderByDescending(i => i.RiskScore).ThenByDescending(i => i.CreatedAt).ToList();

                Action updateAction = () =>
                {
                    Incidents.Clear();
                    foreach (var inc in sorted)
                    {
                        Incidents.Add(inc);
                    }

                    HasNoIncidents = Incidents.Count == 0;
                    ActiveIncidentCount = Incidents.Count(i => i.Status is "Active" or "Contained" or "ObservationOnly");

                    if (Incidents.Count > 0)
                    {
                        if (SelectedIncident == null || !Incidents.Any(i => i.IncidentId == SelectedIncident.IncidentId))
                        {
                            SelectedIncident = Incidents.First();
                        }
                    }
                    else
                    {
                        SelectedIncident = null;
                    }
                };

                if (Application.Current?.Dispatcher != null && !Application.Current.Dispatcher.CheckAccess())
                {
                    Application.Current.Dispatcher.Invoke(updateAction);
                }
                else
                {
                    updateAction();
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Olaylar yüklenirken hata: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }

        private SecurityIncident ConvertFindingToIncident(SecurityFinding f) => FindingIncidentProjection.Create(f);

        private SecurityIncident ConvertQuarantineToIncident(QuarantineEntry q)
        {
            return new SecurityIncident
            {
                IncidentId = $"QUAR-{q.Id:D4}",
                CreatedAt = q.QuarantinedAt,
                Title = !string.IsNullOrWhiteSpace(q.Reason) ? q.Reason : "Karantinaya Alınan Tehdit",
                ThreatName = !string.IsNullOrWhiteSpace(q.Reason) ? q.Reason : "Zararlı / Şüpheli Dosya",
                RootProcessName = "İlişkilendirilmedi",
                RootExecutablePath = q.OriginalPath,
                RootHashSha256 = q.SHA256,
                RiskScore = q.RiskLevel == RiskLevel.ConfirmedMalicious ? 95 : (q.RiskLevel == RiskLevel.HighRisk ? 85 : 70),
                RiskLevel = q.RiskLevel.ToString().ToUpperInvariant(),
                Status = "Quarantined",
                ActionTaken = "Karantina kaydı mevcut; süreç müdahalesi doğrulanmadı",
                HumanExplanation = $"Kasa kaydı: {q.Reason}. Kayıt tek başına süreç sonlandırma veya mevcut dosyanın zararlılık kanıtı değildir. Orijinal yol: {q.OriginalPath}",
                RecommendedUserAction = "Kaydı inceleyin. Geri yükleme, hizmetin yetkilendirme ve bütünlük kontrolünü gerektirir.",
                Timeline = new List<string>
                {
                    $"{q.QuarantinedAt:HH:mm:ss} | [Kasa kaydı] {q.FileName}",
                    $"{q.QuarantinedAt:HH:mm:ss} | [Konum] {q.OriginalPath}",
                    $"{q.QuarantinedAt:HH:mm:ss} | [SHA-256] {q.SHA256}"
                }
            };
        }

        /// <summary>Shows the acknowledged recovery result after refreshing records; failure never deletes content, and busy state always clears.</summary>
        [RelayCommand]
        public async Task RestoreItemAsync(QuarantineEntry? entry)
        {
            var target = entry ?? SelectedItem;
            if (target == null || _quarantineService == null) return;

            IsLoading = true;
            StatusMessage = $"'{target.FileName}' geri yükleniyor...";

            try
            {
                bool success = false;
                string? errorReason = null;
                try { success = await Task.Run(() => _quarantineService.RestoreFileAsync(target.Id)); }
                catch (Exception exception)
                {
                    errorReason = exception.Message;
                    Serilog.Log.Warning(exception, "Recovery has no confirmed result for quarantine entry {Id}.", target.Id);
                }
                if (!success) errorReason ??= _quarantineService.LastError ?? "Dosya geri yüklenemedi veya hizmet sonucu doğrulanamadı.";
                await LoadItemsAsync();
                await LoadIncidentsAsync();
                StatusMessage = success
                    ? $"'{target.FileName}' orijinal konumuna ({target.OriginalPath}) geri yüklendi."
                    : $"Geri yükleme başarısız: {errorReason}";
                _toastService?.ShowToast(success ? "Dosya Geri Yüklendi" : "Geri Yükleme Başarısız",
                    StatusMessage, success ? "Success" : "Warning");
            }
            finally { IsLoading = false; }
        }

        [RelayCommand]
        public void CopyOriginalPath()
        {
            if (SelectedItem != null && !string.IsNullOrEmpty(SelectedItem.OriginalPath))
            {
                try
                {
                    Clipboard.SetText(SelectedItem.OriginalPath);
                    StatusMessage = "Orijinal dosya yolu panoya kopyalandı.";
                }
                catch { }
            }
        }

        [RelayCommand]
        public void CopySha256()
        {
            if (SelectedItem != null && !string.IsNullOrEmpty(SelectedItem.SHA256))
            {
                try
                {
                    Clipboard.SetText(SelectedItem.SHA256);
                    StatusMessage = "SHA-256 karması panoya kopyalandı.";
                }
                catch { }
            }
        }

        /// <summary>Requests explicit permanent deletion without granting trust; reports the receipt after refresh and always clears busy state.</summary>
        [RelayCommand]
        public async Task DeleteItemAsync(QuarantineEntry? entry)
        {
            var target = entry ?? SelectedItem;
            if (target == null || _quarantineService == null) return;

            IsLoading = true;
            StatusMessage = $"'{target.FileName}' kalıcı olarak siliniyor...";

            try
            {
                bool success = false;
                string? errorReason = null;
                try { success = await Task.Run(() => _quarantineService.DeleteQuarantinedAsync(target.Id)); }
                catch (Exception exception)
                {
                    errorReason = exception.Message;
                    Serilog.Log.Warning(exception, "Deletion has no confirmed result for quarantine entry {Id}.", target.Id);
                }
                if (!success) errorReason ??= _quarantineService.LastError ?? "Dosya silinemedi veya hizmet sonucu doğrulanamadı.";
                await LoadItemsAsync();
                await LoadIncidentsAsync();
                StatusMessage = success ? $"'{target.FileName}' diskten kalıcı olarak silindi."
                    : $"Silme işlemi başarısız: {errorReason}";
                _toastService?.ShowToast(success ? "Kalıcı Olarak Silindi" : "Silme İşlemi Başarısız",
                    StatusMessage, success ? "Info" : "Warning");
            }
            finally { IsLoading = false; }
        }

        /// <summary>Acknowledges review only; never creates trust, resolves malware or deletes quarantine content.</summary>
        [RelayCommand]
        public async Task RemediateIncidentAsync(SecurityIncident? incident)
        {
            var target = incident ?? SelectedIncident;
            if (target == null) return;
            IsLoading = true;
            try
            {
                if (_behaviorEngine != null && target.IncidentId.StartsWith("INC-", StringComparison.OrdinalIgnoreCase))
                    await _behaviorEngine.RemediateIncidentAsync(target.IncidentId);
                target.Status = "Reviewed";
                target.ActionTaken = "None";
                OnPropertyChanged(nameof(SelectedIncident));
                ActiveIncidentCount = Incidents.Count(i => i.Status is "Active" or "Contained" or "ObservationOnly");
                StatusMessage = "Olay incelendi. Dosya/süreç değiştirilmedi, muafiyet eklenmedi; temizleme veya engelleme doğrulanmadı.";
                _toastService?.ShowToast("İnceleme kaydedildi", StatusMessage, "Info");
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Incident review acknowledgement failed.");
                StatusMessage = "İnceleme kaydedilemedi; hiçbir güvenlik eylemi doğrulanmadı.";
            }
            finally { IsLoading = false; }
        }

        [RelayCommand]
        public async Task QuarantineSourceFileAsync(SecurityIncident? incident)
        {
            var target = incident ?? SelectedIncident;
            if (target == null || _quarantineService == null) return;

            if (!string.IsNullOrEmpty(target.RootExecutablePath))
            {
                var ok = await _quarantineService.QuarantineFileAsync(target.RootExecutablePath, target.ThreatName);
                if (ok)
                {
                    target.Status = "Quarantined";
                    target.ActionTaken = "Dosya Karantinaya Alındı";
                    OnPropertyChanged(nameof(SelectedIncident));
                    ActiveIncidentCount = Incidents.Count(i => i.Status is "Active" or "Contained" or "ObservationOnly");
                    StatusMessage = $"Zararlı dosya karantina kasasına kilitlendi: {target.RootExecutablePath}";
                    _toastService?.ShowToast("Karantina Başarılı", StatusMessage, "Success");
                    await LoadItemsAsync();
                    await LoadIncidentsAsync();
                }
                else
                {
                    StatusMessage = "Dosya karantinaya alınamadı (Dosya zaten silinmiş veya erişilemiyor).";
                }
            }
        }

        /// <summary>Requests bulk recovery and counts only service-confirmed restores; failures retain the vault copy and never authorize deletion or trust.</summary>
        [RelayCommand]
        public async Task RemoveAllFromQuarantineAsync()
        {
            if (_quarantineService == null || QuarantinedItems == null || QuarantinedItems.Count == 0)
            {
                StatusMessage = "Karantinada geri yüklenecek herhangi bir dosya bulunmuyor.";
                return;
            }

            var itemsToProcess = QuarantinedItems.ToList();
            int restoredCount = 0;
            int unconfirmedCount = 0;
            IsLoading = true;
            try
            {
                for (int i = 0; i < itemsToProcess.Count; i++)
                {
                    var item = itemsToProcess[i];
                    StatusMessage = $"[{i + 1}/{itemsToProcess.Count}] '{item.FileName}' geri yükleniyor...";
                    try
                    {
                        if (await _quarantineService.RestoreFileAsync(item.Id)) restoredCount++;
                        else unconfirmedCount++;
                    }
                    catch (Exception exception)
                    {
                        unconfirmedCount++;
                        Serilog.Log.Warning(exception, "Bulk recovery has no confirmed result for quarantine entry {Id}; no deletion was requested.", item.Id);
                    }
                }

                await LoadItemsAsync();
                await LoadIncidentsAsync();
                StatusMessage = $"{restoredCount} dosyanın geri yüklenmesi doğrulandı; {unconfirmedCount} dosyanın geri yüklenmesi doğrulanamadı. Kalıcı silme veya güven istisnası uygulanmadı.";
                _toastService?.ShowToast(unconfirmedCount == 0 ? "Geri Yükleme Doğrulandı" : "Geri Yükleme Kısmi",
                    StatusMessage, unconfirmedCount == 0 ? "Success" : "Warning");
            }
            finally { IsLoading = false; }
        }
    }
}
