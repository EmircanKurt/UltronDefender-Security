using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class RecommendationsView : Page
    {
        public RecommendationsViewModel ViewModel { get; }

        public RecommendationsView(RecommendationsViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
