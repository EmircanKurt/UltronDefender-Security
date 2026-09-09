using CommunityToolkit.Mvvm.ComponentModel;

namespace AegisPC.App.ViewModels
{
    public partial class ParentalControlsViewModel : ObservableObject
    {
        [ObservableProperty]
        private string pageTitle = "Ebeveyn Denetimi";

        [ObservableProperty]
        private string subTitle = "Bu özellik geliştirme aşamasındadır.";

        [ObservableProperty]
        private string statusBadgeText = "Yakında Gelecek";

        [ObservableProperty]
        private string description = "Çocuklarınız için güvenli bir dijital ortam sağlayan web erişimi filtreleme, zararlı uygulama kısıtlama ve ekran süresi yönetimi özellikleri çok yakında kullanımınıza sunulacaktır.";

        [ObservableProperty]
        private bool isFeatureEnabled = false;

        [ObservableProperty]
        private string statusColor = "#2196F3";
    }
}
