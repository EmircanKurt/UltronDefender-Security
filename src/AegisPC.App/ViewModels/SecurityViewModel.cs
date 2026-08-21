using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class SecurityViewModel : ObservableObject
    {
        private readonly ISecurityFindingService? _findingService;
        private readonly IQuarantineService? _quarantineService;
        private readonly IAllowlistService? _allowlistService;
        private List<SecurityFinding> _allFindings = new();

        [ObservableProperty]
        private string pageTitle = "Güvenlik Merkezi ve Tehdit Bulguları";

        [ObservableProperty]
        private ObservableCollection<SecurityFinding> findings = new();

        [ObservableProperty]
        private SecurityFinding? selectedFinding;

        [ObservableProperty]
        private string searchText = string.Empty;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        public SecurityViewModel(
            ISecurityFindingService? findingService = null,
            IQuarantineService? quarantineService = null,
            IAllowlistService? allowlistService = null)
        {
            _findingService = findingService;
            _quarantineService = quarantineService;
            _allowlistService = allowlistService;
            _ = LoadFindingsAsync();
        }

        partial void OnSearchTextChanged(string value) => FilterFindings();

        private void FilterFindings()
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                Findings = new ObservableCollection<SecurityFinding>(_allFindings);
            }
            else
            {
                var filtered = _allFindings.Where(f =>
                    f.ObjectName.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    f.ObjectPath.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
                    f.Title.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
                Findings = new ObservableCollection<SecurityFinding>(filtered);
            }
        }

        [RelayCommand]
        public async Task LoadFindingsAsync()
        {
            if (_findingService == null) return;

            IsLoading = true;
            StatusMessage = "Güvenlik bulguları yükleniyor...";
            try
            {
                _allFindings = await _findingService.GetAllFindingsAsync();
                FilterFindings();
                StatusMessage = $"Toplam {_allFindings.Count} güvenlik tespiti mevcut.";
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
        public async Task QuarantineFindingAsync(SecurityFinding? finding)
        {
            var target = finding ?? SelectedFinding;
            if (target == null || _quarantineService == null || _findingService == null) return;

            StatusMessage = $"'{target.ObjectName}' karantinaya alınıyor...";
            bool success = await _quarantineService.QuarantineFileAsync(target.ObjectPath, target.Description);

            if (success)
            {
                target.Status = FindingStatus.Resolved;
                await _findingService.UpdateFindingAsync(target);
                StatusMessage = $"'{target.ObjectName}' başarıyla karantinaya alındı.";
                await LoadFindingsAsync();
            }
            else
            {
                StatusMessage = "Karantinaya alma başarısız oldu. Dosya kilitli veya mevcut değil.";
            }
        }

        [RelayCommand]
        public async Task AllowlistFindingAsync(SecurityFinding? finding)
        {
            var target = finding ?? SelectedFinding;
            if (target == null || _allowlistService == null || _findingService == null) return;

            var entry = new AllowlistEntry
            {
                FilePath = target.ObjectPath,
                FileName = target.ObjectName,
                SHA256 = target.SHA256 ?? string.Empty,
                Reason = "Kullanıcı tarafından güvenli olarak işaretlendi.",
                AddedBy = "Kullanıcı"
            };

            await _allowlistService.AddToAllowlistAsync(entry);
            target.IsAllowlisted = true;
            target.Status = FindingStatus.Ignored;
            await _findingService.UpdateFindingAsync(target);

            StatusMessage = $"'{target.ObjectName}' güvenli listeye (Allowlist) eklendi.";
            await LoadFindingsAsync();
        }
    }
}
