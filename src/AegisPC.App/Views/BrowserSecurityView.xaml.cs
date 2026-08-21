using System.Windows.Controls;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class BrowserSecurityView : Page
    {
        public BrowserSecurityViewModel ViewModel { get; }

        public BrowserSecurityView(BrowserSecurityViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
