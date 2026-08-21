using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class StartupManagerView : Page
    {
        public StartupManagerViewModel ViewModel { get; }

        public StartupManagerView(StartupManagerViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
