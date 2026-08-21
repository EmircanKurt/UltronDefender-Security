using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class CrashAnalysisView : Page
    {
        public CrashAnalysisViewModel ViewModel { get; }

        public CrashAnalysisView(CrashAnalysisViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
