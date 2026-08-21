using System.Windows.Controls;
using System.Windows.Input;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class RansomwareShieldView : Page
    {
        public RansomwareShieldView(RansomwareShieldViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
        }

        private void OnPagePreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (e.OriginalSource is System.Windows.DependencyObject depObj)
            {
                if (FindVisualParent<ListView>(depObj) != null || FindVisualParent<DataGrid>(depObj) != null)
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

        private static T? FindVisualParent<T>(System.Windows.DependencyObject child) where T : System.Windows.DependencyObject
        {
            var parentObject = System.Windows.Media.VisualTreeHelper.GetParent(child);
            if (parentObject == null) return null;
            if (parentObject is T parent) return parent;
            return FindVisualParent<T>(parentObject);
        }
    }
}
