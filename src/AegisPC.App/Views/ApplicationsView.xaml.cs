using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class ApplicationsView : Page
    {
        public ApplicationsViewModel ViewModel { get; }

        public ApplicationsView(ApplicationsViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
