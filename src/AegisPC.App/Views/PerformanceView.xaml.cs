using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using AegisPC.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace AegisPC.App.Views
{
    public partial class PerformanceView : Page
    {
        public PerformanceViewModel ViewModel { get; }

        public PerformanceView() : this(App.ServiceProvider != null 
            ? (App.ServiceProvider.GetService<PerformanceViewModel>() ?? new PerformanceViewModel()) 
            : new PerformanceViewModel())
        {
        }

        public PerformanceView(PerformanceViewModel viewModel)
        {
            ViewModel = viewModel;
            DataContext = ViewModel;
            InitializeComponent();

            Loaded += (s, e) =>
            {
                ViewModel.StartLiveMonitoring();
            };

            Unloaded += (s, e) =>
            {
                ViewModel.StopLiveMonitoring();
                ViewModel.Dispose();
            };
        }
    }
}
