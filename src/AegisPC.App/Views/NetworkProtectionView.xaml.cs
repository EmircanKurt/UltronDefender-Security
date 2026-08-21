using System.Windows.Controls;
using System.Windows.Input;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class NetworkProtectionView : Page
    {
        public NetworkProtectionView(NetworkProtectionViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
        }

        private void OnPagePreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (RootScrollViewer != null && e.Delta != 0)
            {
                RootScrollViewer.ScrollToVerticalOffset(RootScrollViewer.VerticalOffset - (e.Delta * 0.75));
                e.Handled = true;
            }
        }
    }
}
