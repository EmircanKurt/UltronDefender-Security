using System;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
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

            UpdateThemeButtonState();
            AegisPC.App.Services.AppThemeManager.ThemeChanged += (theme) =>
            {
                Dispatcher.InvokeAsync(UpdateThemeButtonState);
            };

            RootNavigation.Navigated += (sender, args) =>
            {
                if (args.Page is FrameworkElement fe)
                {
                    ApplyPageEntranceAnimation(fe);
                }
            };

            // Auto-navigate to Dashboard or Scan when window loads
            Loaded += (s, e) =>
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
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine($"MainWindow initial navigation failed: {ex}");
                }
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

        public void NavigateToQuarantine(bool showIncidentsTab = false)
        {
            Dispatcher.Invoke(() =>
            {
                try
                {
                    RootNavigation.Navigate(typeof(Views.QuarantineView));
                    var vm = App.ServiceProvider?.GetService(typeof(ViewModels.QuarantineViewModel)) as ViewModels.QuarantineViewModel
                             ?? ViewModels.QuarantineViewModel.Current;
                    if (vm != null)
                    {
                        vm.NavigateToTab(showIncidentsTab);
                    }
                }
                catch { }
            });
        }

        private void OnThemeToggleClicked(object sender, RoutedEventArgs e)
        {
            AegisPC.App.Services.AppThemeManager.ToggleTheme();
        }

        private void UpdateThemeButtonState()
        {
            if (NavThemeToggle != null && NavThemeIcon != null)
            {
                if (AegisPC.App.Services.AppThemeManager.IsDarkMode)
                {
                    NavThemeToggle.Content = "Açık Tema";
                    NavThemeIcon.Symbol = SymbolRegular.DarkTheme24;
                }
                else
                {
                    NavThemeToggle.Content = "Koyu Tema";
                    NavThemeIcon.Symbol = SymbolRegular.DarkTheme24;
                }
            }
        }

        /// <summary>
        /// Sayfa geçişlerinde 180 ms'lik opaklık 0→1 ve 12 px yukarı kayma giriş animasyonu uygular.
        /// Windows "Animasyonları kapat" (ReduceMotion) ayarı aktifse animasyon atlanır.
        /// </summary>
        private void ApplyPageEntranceAnimation(FrameworkElement element)
        {
            if (element == null) return;

            // ReduceMotion: Windows "Animasyonları kapat" ayarı açıksa animasyonları atla
            if (!SystemParameters.ClientAreaAnimation)
            {
                element.Opacity = 1.0;
                if (element.RenderTransform is TranslateTransform ttReset)
                {
                    ttReset.Y = 0;
                }
                return;
            }

            try
            {
                var duration = TimeSpan.FromMilliseconds(180);
                var cubicEase = new CubicEase { EasingMode = EasingMode.EaseOut };

                var opacityAnim = new DoubleAnimation
                {
                    From = 0.0,
                    To = 1.0,
                    Duration = duration,
                    EasingFunction = cubicEase,
                    FillBehavior = FillBehavior.HoldEnd
                };

                TranslateTransform translateTransform;
                if (element.RenderTransform is TranslateTransform tt)
                {
                    translateTransform = tt;
                }
                else if (element.RenderTransform is TransformGroup tg)
                {
                    var existingTt = tg.Children.OfType<TranslateTransform>().FirstOrDefault();
                    if (existingTt != null)
                    {
                        translateTransform = existingTt;
                    }
                    else
                    {
                        translateTransform = new TranslateTransform(0, 12);
                        tg.Children.Add(translateTransform);
                    }
                }
                else
                {
                    translateTransform = new TranslateTransform(0, 12);
                    element.RenderTransform = translateTransform;
                }

                var translateAnim = new DoubleAnimation
                {
                    From = 12.0,
                    To = 0.0,
                    Duration = duration,
                    EasingFunction = cubicEase,
                    FillBehavior = FillBehavior.HoldEnd
                };

                element.BeginAnimation(UIElement.OpacityProperty, opacityAnim);
                translateTransform.BeginAnimation(TranslateTransform.YProperty, translateAnim);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Sayfa geçiş animasyonu uygulanırken hata oluştu.");
            }
        }
    }
}
