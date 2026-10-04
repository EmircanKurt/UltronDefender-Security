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
        private bool hasNoQuarantinedItems = true;

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
            if (_quarantineService == null) return;

            IsLoading = true;
            StatusMessage = "Karantinadaki öğeler yükleniyor...";
            try
            {
                var items = await _quarantineService.GetQuarantinedItemsAsync();
                QuarantinedItems = new ObservableCollection<QuarantineEntry>(items);
                HasNoQuarantinedItems = QuarantinedItems.Count == 0;
                CanRemoveAll = QuarantinedItems.Count > 0;
                StatusMessage = $"Karantinada {QuarantinedItems.Count} adet etkisizleştirilmiş dosya bulunuyor.";
            }
            catch (Exception ex)
            {
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

        private SecurityIncident ConvertFindingToIncident(SecurityFinding f)
        {
            var fileName = System.IO.Path.GetFileName(f.ObjectPath);
            if (string.IsNullOrEmpty(fileName)) fileName = f.Title;

            bool isResolved = f.Status == FindingStatus.Resolved || f.IsAllowlisted;
            bool isIgnored = f.Status == FindingStatus.Ignored;

            return new SecurityIncident
            {
                IncidentId = $"FIND-{(f.Id != Guid.Empty ? f.Id.ToString("N") : Guid.NewGuid().ToString("N"))}".ToUpperInvariant(),
                CreatedAt = f.CreatedAt,
                Title = f.Title,
                ThreatName = f.Title,
                RootProcessName = fileName,
                RootExecutablePath = f.ObjectPath,
                RootHashSha256 = f.SHA256,
                RiskScore = f.RiskScore,
                RiskLevel = f.RiskLevel.ToString().ToUpperInvariant(),
                Status = isResolved ? "Remediated" : (isIgnored ? "Ignored" : "Active"),
                ActionTaken = isResolved ? "Çözüldü / İzin Verildi" : "İnceleme Bekleniyor",
                HumanExplanation = $"Bu dosya '{f.Title}' olarak tespit edildi. {f.Description} Dosya konumu: {f.ObjectPath}",
                RecommendedUserAction = "Dosyayı Karantina Kasasına kilitleyin veya inceleyip temizleyin.",
                Timeline = new List<string>
                {
                    $"{f.CreatedAt:HH:mm:ss} | [Tespit] Antivirüs tarama motoru şüpheli nesneyi yakaladı (Kategori: {f.Category}).",
                    $"{f.CreatedAt:HH:mm:ss} | [Risk Değerlendirmesi] Tehdit skoru hesaplandı: {f.RiskScore}/100 ({f.RiskLevel}).",
                    $"{f.CreatedAt:HH:mm:ss} | [Dosya Yolu] {f.ObjectPath}"
                },
                Evidences = new List<BehaviorEvidence>
                {
                    new BehaviorEvidence
                    {
                        Type = "StaticScannerHeuristic",
                        Source = f.ObjectPath,
                        Target = f.Title,
                        Explanation = f.Description,
                        Severity = f.RiskScore,
                        Confidence = 0.95
                    }
                }
            };
        }

        private SecurityIncident ConvertQuarantineToIncident(QuarantineEntry q)
        {
            return new SecurityIncident
            {
                IncidentId = $"QUAR-{q.Id:D4}",
                CreatedAt = q.QuarantinedAt,
                Title = !string.IsNullOrWhiteSpace(q.Reason) ? q.Reason : "Karantinaya Alınan Tehdit",
                ThreatName = !string.IsNullOrWhiteSpace(q.Reason) ? q.Reason : "Zararlı / Şüpheli Dosya",
                RootProcessName = q.FileName,
                RootExecutablePath = q.OriginalPath,
                RootHashSha256 = q.SHA256,
                RiskScore = q.RiskLevel == RiskLevel.ConfirmedMalicious ? 95 : (q.RiskLevel == RiskLevel.HighRisk ? 85 : 70),
                RiskLevel = q.RiskLevel.ToString().ToUpperInvariant(),
                Status = "Quarantined",
                ActionTaken = "Karantina Kasasına Kilitlendi (AES-256)",
                HumanExplanation = $"Bu dosya '{q.Reason}' tespiti nedeniyle AES-256 şifreli karantina kasasına kilitlenmiştir. Sistem güvenliğiniz için dosyanın çalışması durdurulmuştur. Orijinal yol: {q.OriginalPath}",
                RecommendedUserAction = "Dosya karantinada güvendedir. Yanlış tespit olduğunu düşünüyorsanız Karantina sekmesinden geri yükleyebilirsiniz.",
                Timeline = new List<string>
                {
                    $"{q.QuarantinedAt:HH:mm:ss} | [Tespit & Müdahale] Dosya tespit edildi ve karantinaya alındı.",
                    $"{q.QuarantinedAt:HH:mm:ss} | [Şifreleme] AES-256 ile kasaya kilitlendi: {q.FileName}",
                    $"{q.QuarantinedAt:HH:mm:ss} | [Konum] {q.OriginalPath}",
                    $"{q.QuarantinedAt:HH:mm:ss} | [SHA-256] {q.SHA256}"
                }
            };
        }

        [RelayCommand]
        public async Task RestoreItemAsync(QuarantineEntry? entry)
        {
            var target = entry ?? SelectedItem;
            if (target == null || _quarantineService == null) return;

            IsLoading = true;
            StatusMessage = $"'{target.FileName}' geri yükleniyor...";

            bool success = false;
            await Task.Run(async () =>
            {
                success = await _quarantineService.RestoreFileAsync(target.Id);
            });

            if (success)
            {
                StatusMessage = $"'{target.FileName}' orijinal konumuna ({target.OriginalPath}) geri yüklendi.";
                _toastService?.ShowToast("Dosya Geri Yüklendi", StatusMessage, "Success");
                await LoadItemsAsync();
                await LoadIncidentsAsync();
            }
            else
            {
                var errorReason = _quarantineService.LastError ?? "Bilinmeyen bir hata oluştu veya dosya geri yüklenemedi.";
                StatusMessage = $"Geri yükleme başarısız: {errorReason}";
                _toastService?.ShowToast("Geri Yükleme Başarısız", StatusMessage, "Warning");
                await LoadItemsAsync();
                await LoadIncidentsAsync();
            }
            IsLoading = false;
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

        [RelayCommand]
        public async Task DeleteItemAsync(QuarantineEntry? entry)
        {
            var target = entry ?? SelectedItem;
            if (target == null || _quarantineService == null) return;

            IsLoading = true;
            StatusMessage = $"'{target.FileName}' kalıcı olarak siliniyor...";

            bool success = false;
            await Task.Run(async () =>
            {
                success = await _quarantineService.DeleteQuarantinedAsync(target.Id);
            });

            if (success)
            {
                StatusMessage = $"'{target.FileName}' diskten kalıcı olarak silindi.";
                _toastService?.ShowToast("Kalıcı Olarak Silindi", StatusMessage, "Info");
                await LoadItemsAsync();
                await LoadIncidentsAsync();
            }
            else
            {
                StatusMessage = "Silme işlemi başarısız.";
            }
            IsLoading = false;
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

        [RelayCommand]
        public async Task RemoveAllFromQuarantineAsync()
        {
            if (_quarantineService == null || QuarantinedItems == null || QuarantinedItems.Count == 0)
            {
                StatusMessage = "Karantinada kaldırılacak herhangi bir dosya bulunmuyor.";
                return;
            }

            var itemsToProcess = QuarantinedItems.ToList();
            int total = itemsToProcess.Count;
            StatusMessage = $"{total} adet dosya karantinadan kaldırılıyor...";
            IsLoading = true;

            int restoredCount = 0;
            int removedCount = 0;

            await Task.Run(async () =>
            {
                for (int i = 0; i < itemsToProcess.Count; i++)
                {
                    var item = itemsToProcess[i];
                    int currentIdx = i + 1;

                    Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        StatusMessage = $"[{currentIdx}/{total}] '{item.FileName}' kaldırılıyor...";
                    });

                    try
                    {
                        // 1. Orijinal konumuna geri yüklemeyi dene
                        bool restored = await _quarantineService.RestoreFileAsync(item.Id);
                        if (restored)
                        {
                            restoredCount++;
                        }
                        else
                        {
                            // Geri yüklenemiyorsa karantina kasasından tamamen silerek kaldır
                            bool deleted = await _quarantineService.DeleteQuarantinedAsync(item.Id);
                            if (deleted)
                            {
                                removedCount++;
                            }
                        }

                        // 2. İlgili güvenlik bulgusunu (finding) çözüldü olarak güncelle
                        if (_findingService != null)
                        {
                            var findings = await _findingService.GetAllFindingsAsync();
                            var matching = findings?.Where(f => f.ObjectPath.Equals(item.OriginalPath, StringComparison.OrdinalIgnoreCase)).ToList();
                            if (matching != null)
                            {
                                foreach (var f in matching)
                                {
                                    f.Status = FindingStatus.Resolved;
                                    f.IsAllowlisted = true;
                                    await _findingService.UpdateFindingAsync(f);
                                }
                            }
                        }

                        // 3. Allowlist Service registration so future scans ignore it
                        if (_allowlistService != null && !string.IsNullOrWhiteSpace(item.OriginalPath))
                        {
                            try
                            {
                                var aEntry = new AllowlistEntry
                                {
                                    FilePath = item.OriginalPath,
                                    FileName = item.FileName,
                                    SHA256 = item.SHA256 ?? string.Empty,
                                    Reason = "Kullanıcı tarafından karantinadan temizlendi/çözüldü.",
                                    AddedBy = "Kullanıcı (Karantina)",
                                    AddedAt = DateTime.UtcNow,
                                    IsActive = true
                                };
                                await _allowlistService.AddToAllowlistAsync(aEntry);
                            }
                            catch { }
                        }

                        // 4. Dismissed listesine ekle
                        _dismissedIncidentIds.Add($"QUAR-{item.Id:D4}");
                        if (!string.IsNullOrEmpty(item.OriginalPath))
                        {
                            _dismissedIncidentIds.Add(item.OriginalPath);
                        }
                    }
                    catch
                    {
                        try
                        {
                            await _quarantineService.DeleteQuarantinedAsync(item.Id);
                            removedCount++;
                        }
                        catch { }
                    }
                }

                // 4. Değişiklikleri otomatik olarak diske kaydet
                if (_settingsService != null)
                {
                    try
                    {
                        _settingsService.SetSetting("DismissedIncidentIds", _dismissedIncidentIds.ToList());
                        await _settingsService.SaveAsync();
                    }
                    catch { }
                }
            });

            await LoadItemsAsync();
            await LoadIncidentsAsync();

            StatusMessage = $"İşlem tamamlandı: {restoredCount} dosya geri yüklendi, {removedCount} dosya kasadan kaldırıldı. Tüm değişiklikler kaydedildi.";
            _toastService?.ShowToast("Karantina Temizlendi", StatusMessage, "Success");
            IsLoading = false;
        }
    }
}
