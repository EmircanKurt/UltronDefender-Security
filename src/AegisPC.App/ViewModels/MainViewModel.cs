using CommunityToolkit.Mvvm.ComponentModel;

namespace AegisPC.App.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        [ObservableProperty]
        private string applicationTitle = "Ultron Defender Total Security";

        [ObservableProperty]
        private string applicationVersion = "v3.2.0";

        [ObservableProperty]
        private bool isServiceConnected = true;

        [ObservableProperty]
        private string statusMessage = "Tüm koruma modülleri aktif ve güncel.";
    }
}
