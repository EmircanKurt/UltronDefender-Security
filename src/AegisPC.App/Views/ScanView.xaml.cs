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

            Loaded += (s, e) =>
            {
                ViewModel.SyncWithScanCoordinator();
            };
        }

        private void OnPagePreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (RootScrollViewer != null && e.Delta != 0)
            {
                RootScrollViewer.ScrollToVerticalOffset(RootScrollViewer.VerticalOffset - (e.Delta * 0.75));
                e.Handled = true;
            }
        }

        private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
        {
            var parentObj = VisualTreeHelper.GetParent(child);
            if (parentObj == null) return null;
            if (parentObj is T parent) return parent;
            return FindVisualParent<T>(parentObj);
        }
    }
}
