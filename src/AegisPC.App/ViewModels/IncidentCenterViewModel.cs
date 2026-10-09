using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.App.Services;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class IncidentCenterViewModel : ObservableObject, IDisposable
    {
        private readonly IBehaviorEngine? _behaviorEngine;
        private readonly ISecurityFindingService? _findingService;
        private readonly IScanCoordinatorService? _scanCoordinator;
        private readonly IQuarantineService? _quarantineService;
        private readonly IWindowsToastNotificationService? _toastService;
        private readonly ISettingsService? _settingsService;
        private readonly IAllowlistService? _allowlistService;
        private readonly HashSet<string> _dismissedIncidentIds = new(StringComparer.OrdinalIgnoreCase);
        private readonly Action<SecurityIncident>? _incidentCreatedHandler;
        private readonly Action<ScanResult>? _scanCompletedHandler;

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
            IWindowsToastNotificationService? toastService = null,
            ISettingsService? settingsService = null,
            IAllowlistService? allowlistService = null)
        {
            _behaviorEngine = behaviorEngine;
            _findingService = findingService;
            _scanCoordinator = scanCoordinator;
            _quarantineService = quarantineService;
            _toastService = toastService;
            _settingsService = settingsService;
            _allowlistService = allowlistService;

            if (_settingsService != null)
            {
                try
                {
                    var saved = _settingsService.GetSetting<List<string>>("DismissedIncidentIds", new List<string>());
                    if (saved != null)
                    {
                        foreach (var id in saved)
                        {
                            if (!string.IsNullOrWhiteSpace(id)) _dismissedIncidentIds.Add(id);
                        }
                    }
                }
                catch { }
            }

            if (_behaviorEngine != null)
            {
                _incidentCreatedHandler = (incident) =>
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
                _behaviorEngine.OnIncidentCreated += _incidentCreatedHandler;
            }

            if (_scanCoordinator != null)
            {
                _scanCompletedHandler = (result) =>
                {
                    _ = LoadIncidentsAsync();
                };
                _scanCoordinator.ScanCompleted += _scanCompletedHandler;
            }

            _ = LoadIncidentsAsync();
        }

        public void Dispose()
        {
            if (_behaviorEngine != null && _incidentCreatedHandler != null)
            {
                _behaviorEngine.OnIncidentCreated -= _incidentCreatedHandler;
            }
            if (_scanCoordinator != null && _scanCompletedHandler != null)
            {
                _scanCoordinator.ScanCompleted -= _scanCompletedHandler;
            }
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

                // 4. Load Quarantined items if quarantine service is available
                if (_quarantineService != null)
                {
                    try
                    {
                        var qItems = await _quarantineService.GetQuarantinedItemsAsync();
                        if (qItems != null)
                        {
                            foreach (var q in qItems)
                            {
                                if (q.Status != QuarantineStatus.Quarantined) continue;


                                // Keep evidence and action history separate; pathname equality cannot prove containment.
                                var actionRecord = ConvertQuarantineToIncident(q);
                                if (seenEvidenceIds.Add(actionRecord.IncidentId)) combinedList.Add(actionRecord);
                            }
                        }
                    }
                    catch { }
                }

                // Sort by RiskScore Descending (Most dangerous first)
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

                    StatusMessage = HasNoIncidents 
                        ? "Aktif güvenlik olayı bulunmuyor. Sisteminiz koruma altında." 
                        : $"Toplam {Incidents.Count} güvenlik olayı ve tespit edilen tehdit kayıtlı ({ActiveIncidentCount} aktif).";
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
                StatusMessage = $"Hata: {ex.Message}";
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
