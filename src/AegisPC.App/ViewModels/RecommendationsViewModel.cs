using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AegisPC.App.ViewModels
{
    public partial class RecommendationsViewModel : ObservableObject
    {
        private readonly IRecommendationEngine? _recommendationEngine;

        [ObservableProperty]
        private string pageTitle = "Akıllı Sistem ve Güvenlik Önerileri";

        [ObservableProperty]
        private ObservableCollection<Recommendation> recommendations = new();

        [ObservableProperty]
        private Recommendation? selectedRecommendation;

        [ObservableProperty]
        private bool isLoading;

        [ObservableProperty]
        private string statusMessage = string.Empty;

        [ObservableProperty]
        private bool hasNoRecommendations = true;

        public RecommendationsViewModel(IRecommendationEngine? recommendationEngine = null)
        {
            _recommendationEngine = recommendationEngine;
            _ = LoadRecommendationsAsync();
        }

        [RelayCommand]
        public async Task LoadRecommendationsAsync()
        {
            if (_recommendationEngine == null) return;

            IsLoading = true;
            StatusMessage = "Sistem ve güvenlik kuralları değerlendiriliyor...";
            try
            {
                var list = await _recommendationEngine.GenerateRecommendationsAsync();
                Recommendations = new ObservableCollection<Recommendation>(list);
                HasNoRecommendations = Recommendations.Count == 0;
                StatusMessage = $"{Recommendations.Count} adet uygulanabilir öneri hazırlandı.";
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
        public async Task ApplyRecommendationAsync(Recommendation? recommendation)
        {
            var target = recommendation ?? SelectedRecommendation;
            if (target == null || _recommendationEngine == null) return;

            await _recommendationEngine.ApplyRecommendationAsync(target.Id);
            StatusMessage = $"'{target.Title}' önerisi uygulandı.";
            await LoadRecommendationsAsync();
        }

        [RelayCommand]
        public async Task DismissRecommendationAsync(Recommendation? recommendation)
        {
            var target = recommendation ?? SelectedRecommendation;
            if (target == null || _recommendationEngine == null) return;

            await _recommendationEngine.DismissRecommendationAsync(target.Id, forever: true);
            StatusMessage = $"'{target.Title}' önerisi yoksayıldı.";
            await LoadRecommendationsAsync();
        }
    }
}
