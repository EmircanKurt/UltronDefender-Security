using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class IncidentCenterView : Page
    {
        public IncidentCenterViewModel ViewModel { get; }

        public IncidentCenterView(IncidentCenterViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();

            Loaded += async (s, e) =>
            {
                await ViewModel.LoadIncidentsAsync();
            };
        }
    }
}
