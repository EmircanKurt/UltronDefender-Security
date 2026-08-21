using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Windows;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class QuarantineViewModel : ObservableObject
    {
        private readonly IQuarantineService? _quarantineService;

        [ObservableProperty]
        private string pageTitle = "Karantina Kasası";

        [ObservableProperty]
        private ObservableCollection<QuarantineEntry> quarantinedItems = new();

        [ObservableProperty]
        private QuarantineEntry? selectedItem;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        [ObservableProperty]
        private bool hasNoQuarantinedItems = true;

        public QuarantineViewModel(IQuarantineService? quarantineService = null)
        {
            _quarantineService = quarantineService;
            _ = LoadItemsAsync();
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
        public async Task RestoreItemAsync(QuarantineEntry? entry)
        {
            var target = entry ?? SelectedItem;
            if (target == null || _quarantineService == null) return;

            StatusMessage = $"'{target.FileName}' geri yükleniyor...";
            bool success = await _quarantineService.RestoreFileAsync(target.Id);

            if (success)
            {
                StatusMessage = $"'{target.FileName}' orijinal konumuna ({target.OriginalPath}) geri yüklendi.";
                await LoadItemsAsync();
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
                await LoadItemsAsync();
            }
            else
            {
                StatusMessage = "Silme işlemi başarısız.";
            }
        }
    }
}
