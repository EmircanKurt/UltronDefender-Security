using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class WindowsEventsView : Page
    {
        public WindowsEventsViewModel ViewModel { get; }

        public WindowsEventsView(WindowsEventsViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
