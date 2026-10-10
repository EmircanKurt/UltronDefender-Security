using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Media.Animation;
using AegisPC.App.Helpers;
using AegisPC.App.ViewModels;
using AegisPC.App.Views;
using Wpf.Ui.Controls;

namespace AegisPC.App
{
    public static class AppNavigation
    {
        /// <summary>Reveals the main scanner only for an explicit user command, never for background telemetry.</summary>
        public static void ShowScanner()
        {
            var window = MainWindow.Instance;
            if (window == null) return;
            window.ShowAndActivate();
            window.NavigateTo(typeof(ScanView));
        }

        public static void NavigateTo(Type pageType)
        {
            MainWindow.Instance?.NavigateTo(pageType);
        }
    }

    public partial class MainWindow : FluentWindow
    {
        private FrameworkElement? _animatedPage;

        public static MainWindow? Instance { get; private set; }
        public static bool AllowClose { get; set; } = false;

        public MainWindow(MainViewModel viewModel, IServiceProvider serviceProvider)
        {
            Instance = this;
            DataContext = viewModel;
            InitializeComponent();
            RootNavigation.SetServiceProvider(serviceProvider);
            SizeChanged += (_, _) => UpdatePaneLayout();

            UpdateThemeButtonState();
            AegisPC.App.Services.AppThemeManager.ThemeChanged += OnAppThemeChanged;
            SystemParameters.StaticPropertyChanged += OnMotionPreferenceChanged;
            System.Windows.Media.RenderCapability.TierChanged += OnEntranceEnvironmentChanged;
            Deactivated += OnEntranceEnvironmentChanged;
            StateChanged += OnEntranceEnvironmentChanged;
            IsVisibleChanged += OnWindowVisibilityChanged;

            RootNavigation.Navigated += (sender, args) =>
            {
                if (args.Page is FrameworkElement fe)
                {
                    NavigationScrollPolicy.ConfigurePageOwnedScrolling(fe,
                        WheelScrollHelper.FindFirstVisualChild<NavigationViewContentPresenter>(RootNavigation));
                    ApplyPageEntranceAnimation(fe);
                }
            };

            // Auto-navigate to Dashboard or Scan when window loads
            Loaded += (s, e) =>
            {
                try
                {
                    ApplyWindowEntranceAnimation();
                    if (Views.ActiveScanWindow.ActiveInstance != null && Views.ActiveScanWindow.ActiveInstance.IsVisible && Views.ActiveScanWindow.ActiveInstance.Owner == null)
                    {
                        Views.ActiveScanWindow.ActiveInstance.Owner = this;
                    }

                    if (!string.IsNullOrWhiteSpace(Program.PendingStartupScanPath))
                    {
                        var target = Program.PendingStartupScanPath;
                        Program.PendingStartupScanPath = null;
                        NavigateToScanAndScanPath(target);
                    }
                    else
                    {
                        RootNavigation.Navigate(typeof(ScanView));
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine($"MainWindow initial navigation failed: {ex}");
                }
            };
        }

        private void UpdatePaneLayout()
        {
            bool compact = ActualWidth < 900;
            RootNavigation.PaneDisplayMode = compact ? NavigationViewPaneDisplayMode.LeftMinimal : NavigationViewPaneDisplayMode.Left;
            SidebarColumn.Width = new GridLength(compact ? 64 : 240);
            BrandText.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
            BrandHeader.Padding = compact ? new Thickness(10, 20, 10, 20) : new Thickness(20, 26, 16, 26);
            BrandImage.Margin = new Thickness(0, 0, compact ? 0 : 12, 0);
        }

        public void NavigateToScanAndScanPath(string targetPath)
        {
            Dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    ShowAndActivate();
                    NavigateTo(typeof(ScanView));
                    await System.Threading.Tasks.Task.Delay(300);
                    var scanVm = App.ServiceProvider?.GetService(typeof(ScanViewModel)) as ScanViewModel;
                    if (scanVm != null && !string.IsNullOrWhiteSpace(targetPath))
                    {
                        await scanVm.StartCustomPathScanAsync(targetPath);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine($"MainWindow NavigateToScanAndScanPath failed: {ex}");
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
                    App.IsStartMinimized = false;
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

                    if (Views.ActiveScanWindow.ActiveInstance != null && Views.ActiveScanWindow.ActiveInstance.IsVisible)
                    {
                        if (Views.ActiveScanWindow.ActiveInstance.Owner == null)
                        {
                            Views.ActiveScanWindow.ActiveInstance.Owner = this;
                        }
                        Views.ActiveScanWindow.ActiveInstance.Activate();
                    }
                }
                catch (Exception ex) 
                { 
                    Serilog.Log.Warning(ex, "ShowAndActivate window activation failed."); 
                }
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
                catch (Exception ex) 
                { 
                    Serilog.Log.Warning(ex, "Navigation to page {Type} failed.", pageType); 
                }
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
                catch (Exception ex) 
                { 
                    Serilog.Log.Warning(ex, "NavigateToQuarantine failed."); 
                }
            });
        }

        private void OnAppThemeChanged(AegisPC.Core.Enums.ThemeMode theme)
        {
            Dispatcher.InvokeAsync(UpdateThemeButtonState);
        }

        protected override void OnClosed(EventArgs e)
        {
            AegisPC.App.Services.AppThemeManager.ThemeChanged -= OnAppThemeChanged;
            SystemParameters.StaticPropertyChanged -= OnMotionPreferenceChanged;
            System.Windows.Media.RenderCapability.TierChanged -= OnEntranceEnvironmentChanged;
            StopEntranceAnimations();
            base.OnClosed(e);
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
        /// Owns the optional page entrance fade without replacing a page's existing render transform.
        /// The Windows motion preference and rendering tier select the static presentation.
        /// </summary>
        private void ApplyPageEntranceAnimation(FrameworkElement element)
        {
            try
            {
                if (_animatedPage != null) RestoreOpacity(_animatedPage);
                _animatedPage = element;
                RestoreOpacity(element);
                if (CanAnimateEntrance()) ApplyEntranceFade(element, 180);
            }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Page entrance animation failed.");
            }
        }

        private bool CanAnimateEntrance() => UiMotionPolicy.CanAnimate && IsVisible && IsActive && WindowState != WindowState.Minimized;

        private void ApplyWindowEntranceAnimation()
        {
            RestoreOpacity(this);
            if (CanAnimateEntrance()) ApplyEntranceFade(this, 250);
        }

        private static void ApplyEntranceFade(FrameworkElement element, int durationMs)
        {
            var animation = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(durationMs))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
                FillBehavior = FillBehavior.Stop
            };
            animation.Completed += (_, _) => element.BeginAnimation(UIElement.OpacityProperty, null);
            element.BeginAnimation(UIElement.OpacityProperty, animation);
        }

        private static void RestoreOpacity(FrameworkElement element)
        {
            element.BeginAnimation(UIElement.OpacityProperty, null);
            element.Opacity = 1;
        }

        private void StopEntranceAnimations()
        {
            RestoreOpacity(this);
            if (_animatedPage != null) RestoreOpacity(_animatedPage);
        }

        private void OnEntranceEnvironmentChanged(object? sender, EventArgs e)
        {
            if (!CanAnimateEntrance()) StopEntranceAnimations();
        }

        private void OnWindowVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e)
        {
            if (!CanAnimateEntrance()) StopEntranceAnimations();
        }

        private void OnMotionPreferenceChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(SystemParameters.ClientAreaAnimation))
                Dispatcher.InvokeAsync(() => { if (!UiMotionPolicy.CanAnimate) StopEntranceAnimations(); });
        }
    }
}
