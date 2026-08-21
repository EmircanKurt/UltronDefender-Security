using System;
using System.ComponentModel;
using System.Windows;
using AegisPC.App.ViewModels;
using AegisPC.App.Views;
using Wpf.Ui.Controls;

namespace AegisPC.App
{
    public static class AppNavigation
    {
        public static void NavigateTo(Type pageType)
        {
            MainWindow.Instance?.NavigateTo(pageType);
        }
    }

    public partial class MainWindow : FluentWindow
    {
        public static MainWindow? Instance { get; private set; }
        public static bool AllowClose { get; set; } = false;

        public MainWindow(MainViewModel viewModel, IServiceProvider serviceProvider)
        {
            Instance = this;
            DataContext = viewModel;
            InitializeComponent();
            RootNavigation.SetServiceProvider(serviceProvider);

            // Auto-navigate to Dashboard or Scan when window loads
            Loaded += async (s, e) =>
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(Program.PendingStartupScanPath))
                    {
                        var target = Program.PendingStartupScanPath;
                        Program.PendingStartupScanPath = null;
                        NavigateToScanAndScanPath(target);
                    }
                    else
                    {
                        RootNavigation.Navigate(typeof(DashboardView));
                    }
                }
                catch { }
            };
        }

        public void NavigateToScanAndScanPath(string targetPath)
        {
            Dispatcher.InvokeAsync(async () =>
            {
                ShowAndActivate();
                NavigateTo(typeof(ScanView));
                await System.Threading.Tasks.Task.Delay(300);
                var scanVm = App.ServiceProvider?.GetService(typeof(ScanViewModel)) as ScanViewModel;
                if (scanVm != null && !string.IsNullOrWhiteSpace(targetPath))
                {
                    await scanVm.StartCustomPathScanAsync(targetPath);
                }
            });
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            // Kullanıcı X (kapat) butonuna bastığında programı sonlandırmak yerine
            // arka planda korumaya devam etmek için sistem tepsisine (Tray) gizle
            if (!AllowClose)
            {
                e.Cancel = true;
                this.Hide();
            }
            else
            {
                base.OnClosing(e);
            }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SW_RESTORE = 9;

        public void ShowAndActivate()
        {
            Dispatcher.Invoke(() =>
            {
                try
                {
                    if (!IsVisible)
                    {
                        Show();
                    }
                    Visibility = Visibility.Visible;
                    if (WindowState == WindowState.Minimized)
                    {
                        WindowState = WindowState.Normal;
                    }
                    Activate();
                    Topmost = true;
                    Topmost = false;
                    Focus();

                    var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                    if (hwnd != IntPtr.Zero)
                    {
                        ShowWindow(hwnd, SW_RESTORE);
                        SetForegroundWindow(hwnd);
                    }
                }
                catch { }
            });
        }

        public void NavigateTo(Type pageType)
        {
            Dispatcher.Invoke(() =>
            {
                try
                {
                    RootNavigation.Navigate(pageType);
                }
                catch { }
            });
        }
    }
}
