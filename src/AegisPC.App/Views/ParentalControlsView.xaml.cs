using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class ParentalControlsView : Page
    {
        public ParentalControlsView(ParentalControlsViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
        }
    }
}
