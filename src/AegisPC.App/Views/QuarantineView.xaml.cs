using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class QuarantineView : Page
    {
        public QuarantineViewModel ViewModel { get; }

        public QuarantineView(QuarantineViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
