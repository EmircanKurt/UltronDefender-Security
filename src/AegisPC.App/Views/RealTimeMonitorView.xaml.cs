using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class RealTimeMonitorView : Page
    {
        public RealTimeMonitorViewModel ViewModel { get; }

        public RealTimeMonitorView(RealTimeMonitorViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
