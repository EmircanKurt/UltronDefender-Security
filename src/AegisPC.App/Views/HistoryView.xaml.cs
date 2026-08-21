using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class HistoryView : Page
    {
        public HistoryViewModel ViewModel { get; }

        public HistoryView(HistoryViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
