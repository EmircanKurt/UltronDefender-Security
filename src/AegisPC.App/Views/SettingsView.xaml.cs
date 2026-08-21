using System.Windows.Controls;
using System.Windows.Input;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class SettingsView : Page
    {
        public SettingsViewModel ViewModel { get; }

        public SettingsView(SettingsViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
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
