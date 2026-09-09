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
                        if (!_dismissedIncidentIds.Contains(incident.IncidentId) &&
                            (string.IsNullOrEmpty(incident.RootExecutablePath) || !_dismissedIncidentIds.Contains(incident.RootExecutablePath)) &&
                            !Incidents.Any(i => i.IncidentId == incident.IncidentId))
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
                            if (inc.Status != "Remediated" &&
                                !_dismissedIncidentIds.Contains(inc.IncidentId) &&
                                (string.IsNullOrEmpty(inc.RootExecutablePath) || !_dismissedIncidentIds.Contains(inc.RootExecutablePath)))
                            {
                                combinedList.Add(inc);
                            }
                        }
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
                            if (f.Status == FindingStatus.Resolved || f.Status == FindingStatus.Ignored || f.IsAllowlisted)
                            {
                                continue;
                            }

                            var incidentId = $"FIND-{(f.Id != Guid.Empty ? f.Id.ToString("N")[..8] : Guid.NewGuid().ToString("N")[..8])}".ToUpperInvariant();
                            if (_dismissedIncidentIds.Contains(incidentId) || _dismissedIncidentIds.Contains(f.ObjectPath))
                            {
                                continue;
                            }

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
                        if (f.Status == FindingStatus.Resolved || f.Status == FindingStatus.Ignored || f.IsAllowlisted)
                        {
                            continue;
                        }

                        if (_dismissedIncidentIds.Contains(f.ObjectPath))
                        {
                            continue;
                        }

                        if (!combinedList.Any(i => i.RootExecutablePath.Equals(f.ObjectPath, StringComparison.OrdinalIgnoreCase)))
                        {
                            combinedList.Add(ConvertFindingToIncident(f));
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

                                var quarId = $"QUAR-{q.Id:D4}";
                                if (_dismissedIncidentIds.Contains(quarId) || _dismissedIncidentIds.Contains(q.OriginalPath))
                                {
                                    continue;
                                }

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
        public async Task RemediateIncidentAsync(SecurityIncident? incident)
        {
            var target = incident ?? SelectedIncident;
            if (target == null) return;

            IsLoading = true;
            try
            {
                // 1. Mark as remediated in model
                target.Status = "Remediated";
                target.ActionTaken = "Çözüldü Olarak İşaretlendi";

                // 2. Persist in dismissed set
                if (!string.IsNullOrWhiteSpace(target.IncidentId))
                {
                    _dismissedIncidentIds.Add(target.IncidentId);
                }
                if (!string.IsNullOrWhiteSpace(target.RootExecutablePath))
                {
                    _dismissedIncidentIds.Add(target.RootExecutablePath);
                }

                if (_settingsService != null)
                {
                    try
                    {
                        _settingsService.SetSetting("DismissedIncidentIds", _dismissedIncidentIds.ToList());
                        await _settingsService.SaveAsync();
                    }
                    catch { }
                }

                // 3. Behavior Engine remediation if INC-
                if (_behaviorEngine != null && target.IncidentId.StartsWith("INC-", StringComparison.OrdinalIgnoreCase))
                {
                    await _behaviorEngine.RemediateIncidentAsync(target.IncidentId);
                }

                // 4. Finding Service resolution if FIND- or matching path
                if (_findingService != null)
                {
                    try
                    {
                        var findings = await _findingService.GetAllFindingsAsync();
                        var matchingFindings = findings?.Where(f =>
                            (!string.IsNullOrEmpty(target.RootExecutablePath) && f.ObjectPath.Equals(target.RootExecutablePath, StringComparison.OrdinalIgnoreCase)) ||
                            target.IncidentId.EndsWith(f.Id.ToString("N")[..8], StringComparison.OrdinalIgnoreCase)
                        ).ToList();

                        if (matchingFindings != null)
                        {
                            foreach (var f in matchingFindings)
                            {
                                f.Status = FindingStatus.Resolved;
                                f.IsAllowlisted = true;
                                await _findingService.UpdateFindingAsync(f);

                                if (_allowlistService != null && !string.IsNullOrWhiteSpace(f.ObjectPath))
                                {
                                    try
                                    {
                                        var fEntry = new AllowlistEntry
                                        {
                                            FilePath = f.ObjectPath,
                                            FileName = f.ObjectName,
                                            SHA256 = f.SHA256 ?? string.Empty,
                                            Reason = "Kullanıcı tarafından çözüldü olarak işaretlendi.",
                                            AddedBy = "Kullanıcı (Çözüldü)",
                                            AddedAt = DateTime.UtcNow,
                                            IsActive = true
                                        };
                                        await _allowlistService.AddToAllowlistAsync(fEntry);
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                    catch { }
                }

                // 5. Allowlist Service registration so future scans will NEVER encounter it again
                if (_allowlistService != null && !string.IsNullOrWhiteSpace(target.RootExecutablePath))
                {
                    try
                    {
                        var entry = new AllowlistEntry
                        {
                            FilePath = target.RootExecutablePath,
                            FileName = Path.GetFileName(target.RootExecutablePath),
                            SHA256 = target.RootHashSha256 ?? string.Empty,
                            Reason = "Kullanıcı tarafından çözüldü olarak işaretlendi.",
                            AddedBy = "Kullanıcı (Çözüldü)",
                            AddedAt = DateTime.UtcNow,
                            IsActive = true
                        };
                        await _allowlistService.AddToAllowlistAsync(entry);
                    }
                    catch { }
                }

                // 6. Quarantine Service cleanup if QUAR- or quarantined file
                if (_quarantineService != null)
                {
                    if (target.IncidentId.StartsWith("QUAR-", StringComparison.OrdinalIgnoreCase))
                    {
                        var idPart = target.IncidentId.Replace("QUAR-", "", StringComparison.OrdinalIgnoreCase);
                        if (int.TryParse(idPart, out int quarId))
                        {
                            await _quarantineService.DeleteQuarantinedAsync(quarId);
                        }
                    }

                    if (!string.IsNullOrEmpty(target.RootExecutablePath))
                    {
                        try
                        {
                            var qItems = await _quarantineService.GetQuarantinedItemsAsync();
                            var matchingQuar = qItems?.FirstOrDefault(q => q.OriginalPath.Equals(target.RootExecutablePath, StringComparison.OrdinalIgnoreCase));
                            if (matchingQuar != null)
                            {
                                await _quarantineService.DeleteQuarantinedAsync(matchingQuar.Id);
                            }
                        }
                        catch { }
                    }
                }

                // 6. UI Update: Remove from Incidents list immediately
                Action uiRemove = () =>
                {
                    Incidents.Remove(target);
                    HasNoIncidents = Incidents.Count == 0;
                    ActiveIncidentCount = Incidents.Count(i => i.Status == "Active" || i.Status == "Contained");
                    SelectedIncident = Incidents.FirstOrDefault();
                };

                if (Application.Current?.Dispatcher != null && !Application.Current.Dispatcher.CheckAccess())
                {
                    Application.Current.Dispatcher.Invoke(uiRemove);
                }
                else
                {
                    uiRemove();
                }

                StatusMessage = $"'{target.ThreatName}' olayı çözüldü olarak işaretlendi ve listeden kaldırıldı.";
                _toastService?.ShowToast("Olay Çözüldü", StatusMessage, "Success");
            }
            catch (Exception ex)
            {
                StatusMessage = $"Olay çözülürken hata: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
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
