using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class PerformanceView : Page
    {
        public PerformanceViewModel ViewModel { get; }

        public PerformanceView(PerformanceViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();

            Loaded += async (s, e) =>
            {
                await ViewModel.LoadAsync();
            };
        }

        private void OnPagePreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (e.OriginalSource is DependencyObject depObj)
            {
                if (FindVisualParent<DataGrid>(depObj) != null || 
                    FindVisualParent<ListBox>(depObj) != null || 
                    FindVisualParent<ListView>(depObj) != null || 
                    FindVisualParent<TextBox>(depObj) != null)
                {
                    return;
                }
            }

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
