using System.Windows.Controls;
using System.Windows.Input;
using AegisPC.App.ViewModels;

namespace AegisPC.App.Views
{
    public partial class RansomwareShieldView : Page
    {
        public RansomwareShieldView() 
            : this(App.ServiceProvider != null 
                ? (RansomwareShieldViewModel)(App.ServiceProvider.GetService(typeof(RansomwareShieldViewModel)) ?? new RansomwareShieldViewModel())
                : new RansomwareShieldViewModel())
        {
        }

        public RansomwareShieldView(RansomwareShieldViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
        }
    }
}
