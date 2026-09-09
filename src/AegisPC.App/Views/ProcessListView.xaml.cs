using System.Windows.Controls;
using System.Windows.Input;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class ProcessListView : Page
    {
        public ProcessListViewModel ViewModel { get; }

        public ProcessListView() : this(App.ServiceProvider != null ? (Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetService<ProcessListViewModel>(App.ServiceProvider) ?? new ProcessListViewModel()) : new ProcessListViewModel())
        {
        }

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
