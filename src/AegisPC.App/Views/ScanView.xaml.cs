using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class ScanView : Page
    {
        public ScanViewModel ViewModel { get; }

        public ScanView(ScanViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
            SizeChanged += (_, _) => ScanOptionsGrid.Columns = ActualWidth < 780 ? 1 : 3;

            Loaded += (s, e) =>
            {
                ViewModel.SyncWithScanCoordinator();
            };
        }
    }
}
