using System.Windows.Controls;
using System.Windows.Input;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class ProcessListView : Page
    {
        public ProcessListViewModel ViewModel { get; }

        public ProcessListView(ProcessListViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();

            Loaded += async (s, e) =>
            {
                await ViewModel.LoadProcessesAsync();
            };
        }

        private void OnPagePreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            // DataGrid and detail panel inner scrolling
        }
    }
}
