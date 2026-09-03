using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class IncidentCenterViewModel : ObservableObject
    {
        private readonly IBehaviorEngine? _behaviorEngine;
        private readonly ISecurityFindingService? _findingService;
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly IQuarantineService? _quarantineService;
        private readonly IWindowsToastNotificationService? _toastService;

        [ObservableProperty] private string pageTitle = "Olay ve Tehdit Bildirim Merkezi (Incident Center)";
        [ObservableProperty] private ObservableCollection<SecurityIncident> incidents = new();
        [ObservableProperty] private SecurityIncident? selectedIncident;
        [ObservableProperty] private bool hasNoIncidents = true;
        [ObservableProperty] private bool isLoading = false;
        [ObservableProperty] private string statusMessage = string.Empty;
        [ObservableProperty] private int activeIncidentCount = 0;

        public IncidentCenterViewModel(
            IBehaviorEngine? behaviorEngine = null,
            ISecurityFindingService? findingService = null,
            IScanCoordinatorService? scanCoordinator = null,
            IQuarantineService? quarantineService = null,
            IWindowsToastNotificationService? toastService = null)
        {
            _behaviorEngine = behaviorEngine;
            _findingService = findingService;
            _scanCoordinator = scanCoordinator;
            _quarantineService = quarantineService;
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
                    _ = LoadIncidentsAsync();
                };
            }

            _ = LoadIncidentsAsync();
        }

        [RelayCommand]
        public async Task LoadIncidentsAsync()
        {
            IsLoading = true;
            StatusMessage = "Güvenlik olayları ve tehdit telemetrisi taranıyor...";
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

                // Sort by RiskScore Descending (Most dangerous first)
                var sorted = combinedList.OrderByDescending(i => i.RiskScore).ToList();

                App.Current?.Dispatcher?.Invoke(() =>
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

                    StatusMessage = HasNoIncidents 
                        ? "Aktif güvenlik olayı bulunmuyor. Sisteminiz koruma altında." 
                        : $"Toplam {Incidents.Count} güvenlik olayı ve tespit edilen tehdit kayıtlı ({ActiveIncidentCount} aktif).";
                });
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
                }
                else
                {
                    StatusMessage = "Dosya karantinaya alınamadı (Dosya zaten silinmiş veya erişilemiyor).";
                }
            }
        }
    }
}
