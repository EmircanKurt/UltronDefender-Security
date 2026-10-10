using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using AegisPC.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace AegisPC.App.Views
{
    public partial class DashboardView : Page
    {
        public DashboardViewModel ViewModel { get; }

        public DashboardView() : this(App.ServiceProvider != null 
            ? (App.ServiceProvider.GetService<DashboardViewModel>() ?? new DashboardViewModel()) 
            : new DashboardViewModel())
        {
        }

        public DashboardView(DashboardViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();
        }
    }
}
