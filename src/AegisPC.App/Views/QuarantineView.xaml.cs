using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class QuarantineView : Page
    {
        public QuarantineViewModel ViewModel { get; }

        public QuarantineView() : this(App.ServiceProvider != null ? (Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetService<QuarantineViewModel>(App.ServiceProvider) ?? new QuarantineViewModel()) : new QuarantineViewModel())
        {
        }

        public QuarantineView(QuarantineViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
