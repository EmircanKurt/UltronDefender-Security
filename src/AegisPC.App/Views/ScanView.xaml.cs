using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    /// <summary>Hosts the theme-specific scan chooser and displays existing per-user reports without starting a scan on navigation.</summary>
    public partial class ScanView : Page
    {
        /// <summary>Provides existing scan, resource selection and report commands; the view does not replace engine policy.</summary>
        public ScanViewModel ViewModel { get; }

        /// <summary>Connects presentation and refreshes handled read-only history when loaded; no security action is executed here.</summary>
        public ScanView(ScanViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
            Loaded += async (s, e) =>
            {
                ViewModel.SyncWithScanCoordinator();
                await ViewModel.RefreshReportsAsync();
            };
        }
    }
}
