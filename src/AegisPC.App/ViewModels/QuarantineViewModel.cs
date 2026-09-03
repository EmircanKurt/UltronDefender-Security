using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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

        public QuarantineViewModel(
            IQuarantineService? quarantineService = null,
            IBehaviorEngine? behaviorEngine = null,
            ISecurityFindingService? findingService = null,
            IScanCoordinatorService? scanCoordinator = null,
            IWindowsToastNotificationService? toastService = null)
        {
            _quarantineService = quarantineService;
            _behaviorEngine = behaviorEngine;
            _findingService = findingService;
            _scanCoordinator = scanCoordinator;
            _toastService = toastService;

            if (_behaviorEngine != null)
            {
                _behaviorEngine.OnIncidentCreated += (incident) =>
                {
                    App.Current?.Dispatcher?.Invoke(() =>
                    {
                        if (!Incidents.Any(i => i.IncidentId == incident.IncidentId))
                        {
                            Incidents.Insert(0, incident);
                            while (Incidents.Count > 100)
                            {
                                Incidents.RemoveAt(Incidents.Count - 1);
                            }
                            HasNoIncidents = Incidents.Count == 0;
                            ActiveIncidentCount = Incidents.Count(i => i.Status == "Active" || i.Status == "Contained");
                            if (SelectedIncident == null) SelectedIncident = incident;
                        }
                    });
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
                        combinedList.AddRange(activeList);
                    }
                }

                // 2. Load Persistent Scan Findings from Database
                if (_findingService != null)
                {
                    var findings = await _findingService.GetAllFindingsAsync();
                    if (findings != null)
                    {
                        foreach (var f in findings)
                        {
                            if (!combinedList.Any(i => i.RootExecutablePath.Equals(f.ObjectPath, StringComparison.OrdinalIgnoreCase)))
                            {
                                combinedList.Add(ConvertFindingToIncident(f));
                            }
                        }
                    }
                }

                // 3. Load Current Active Coordinator Findings (Live Scan)
                if (_scanCoordinator?.CurrentFindings != null)
                {
                    foreach (var f in _scanCoordinator.CurrentFindings)
                    {
                        if (!combinedList.Any(i => i.RootExecutablePath.Equals(f.ObjectPath, StringComparison.OrdinalIgnoreCase)))
                        {
                            combinedList.Add(ConvertFindingToIncident(f));
                        }
                    }
                }

                // 4. BI-DIRECTIONAL DATA CONSISTENCY: Quarantined files must appear in Incident History
                if (QuarantinedItems != null && QuarantinedItems.Count > 0)
                {
                    foreach (var q in QuarantinedItems)
                    {
                        var matchingIncident = combinedList.FirstOrDefault(i =>
                            !string.IsNullOrEmpty(i.RootExecutablePath) &&
                            i.RootExecutablePath.Equals(q.OriginalPath, StringComparison.OrdinalIgnoreCase));

                        if (matchingIncident != null)
                        {
                            matchingIncident.Status = "Quarantined";
                            matchingIncident.ActionTaken = "Karantina Kasasına Kilitlendi (AES-256)";
                        }
                        else
                        {
                            combinedList.Add(ConvertQuarantineToIncident(q));
                        }
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
                    ActiveIncidentCount = Incidents.Count(i => i.Status == "Active" || i.Status == "Contained");

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

                if (App.Current?.Dispatcher != null && !App.Current.Dispatcher.CheckAccess())
                {
                    App.Current.Dispatcher.Invoke(updateAction);
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
                IncidentId = $"FIND-{(f.Id != Guid.Empty ? f.Id.ToString("N")[..8] : Guid.NewGuid().ToString("N")[..8])}".ToUpperInvariant(),
                CreatedAt = f.CreatedAt,
                Title = f.Title,
                ThreatName = f.Title,
                RootProcessName = fileName,
                RootExecutablePath = f.ObjectPath,
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

            StatusMessage = $"'{target.FileName}' geri yükleniyor...";
            bool success = await _quarantineService.RestoreFileAsync(target.Id);

            if (success)
            {
                StatusMessage = $"'{target.FileName}' orijinal konumuna ({target.OriginalPath}) geri yüklendi.";
                _toastService?.ShowToast("Dosya Geri Yüklendi", StatusMessage, "Success");
                await LoadItemsAsync();
                await LoadIncidentsAsync();
            }
            else
            {
                StatusMessage = "Dosya geri yüklenemedi.";
            }
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

            StatusMessage = $"'{target.FileName}' kalıcı olarak siliniyor...";
            bool success = await _quarantineService.DeleteQuarantinedAsync(target.Id);

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
        }

        [RelayCommand]
        public async Task RemediateIncidentAsync(SecurityIncident? incident)
        {
            var target = incident ?? SelectedIncident;
            if (target == null) return;

            if (_behaviorEngine != null && target.IncidentId.StartsWith("INC-"))
            {
                await _behaviorEngine.RemediateIncidentAsync(target.IncidentId);
            }

            target.Status = "Remediated";
            target.ActionTaken = "Çözüldü Olarak İşaretlendi";
            OnPropertyChanged(nameof(SelectedIncident));
            ActiveIncidentCount = Incidents.Count(i => i.Status == "Active" || i.Status == "Contained");
            StatusMessage = $"'{target.ThreatName}' olayı çözüldü olarak işaretlendi.";
            _toastService?.ShowToast("Olay Çözüldü", StatusMessage, "Success");
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
                    ActiveIncidentCount = Incidents.Count(i => i.Status == "Active" || i.Status == "Contained");
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
    }
}
